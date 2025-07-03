#!/usr/bin/env python3

import argparse
import os
import re
import sys
import tempfile
import platform
import requests
import textwrap
import uuid
import json
import threading
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.parse import quote, unquote
from typing import Dict, List, Optional, Tuple, Any
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
from dataclasses import dataclass, asdict
import ssl
import certifi
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import hashlib
import hmac
import secrets

@dataclass
class RedirectResult:
    number: int
    url: str
    status_code: int
    next_url: Optional[str] = None
    response_time: float = 0.0
    headers: Dict[str, str] = None
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {}

class SecureSession:
    def __init__(self, verify_ssl: bool = True, timeout: int = 30):
        self.session = requests.Session()
        self.timeout = timeout
        
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'DNT': '1',
            'Sec-GPC': '1',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        if verify_ssl:
            self.session.verify = certifi.where()
        else:
            self.session.verify = False
            requests.packages.urllib3.disable_warnings()

class URLValidator:
    @staticmethod
    def validate_url(url: str) -> bool:
        if not url:
            return False
        
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    @staticmethod
    def sanitize_url(url: str) -> str:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError("Invalid URL format")
        
        return url

class PathValidator:
    @staticmethod
    def validate_output_path(path: str) -> bool:
        if not path:
            return False
        
        if any(dangerous in path for dangerous in ['../', '..\\', '~/', '~\\']):
            return False
        
        if os.path.isabs(path):
            return False
        
        try:
            resolved = os.path.realpath(path)
            current_dir = os.path.realpath(os.getcwd())
            return resolved.startswith(current_dir)
        except Exception:
            return False

class RedirectAnalyzer:
    def __init__(self, max_redirects: int = 30, timeout: int = 30, verify_ssl: bool = True):
        self.max_redirects = max_redirects
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = SecureSession(verify_ssl, timeout)
        self.stopped = False
        
    def extract_location_from_body(self, body: str) -> Optional[str]:
        patterns = [
            r"location\.href\s*=\s*[\"']([^\"']+)[\"']",
            r"window\.location\s*=\s*[\"']([^\"']+)[\"']",
            r"<meta\s+http-equiv=[\"']refresh[\"'][^>]*content=[\"'][^\"']*url=([^\"']+)[\"']"
        ]
        
        for pattern in patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def analyze_redirects(self, url: str, progress_callback=None) -> Tuple[List[RedirectResult], requests.cookies.RequestsCookieJar]:
        redirect_count = 0
        current_url = url
        results = []
        
        while redirect_count < self.max_redirects and not self.stopped:
            try:
                start_time = time.time()
                response = self.session.session.head(
                    current_url, 
                    allow_redirects=False, 
                    timeout=self.timeout
                )
                response_time = time.time() - start_time
                
                result = RedirectResult(
                    number=redirect_count + 1,
                    url=current_url,
                    status_code=response.status_code,
                    response_time=response_time,
                    headers=dict(response.headers)
                )
                
                if 300 <= response.status_code < 400 and 'location' in response.headers:
                    next_url = response.headers['location']
                    result.next_url = next_url
                    
                    if not bool(urlparse(next_url).netloc):
                        next_url = urljoin(current_url, next_url)
                    
                    current_url = next_url
                    redirect_count += 1
                    results.append(result)
                    
                    if progress_callback:
                        progress_callback(redirect_count, current_url)
                else:
                    get_response = self.session.session.get(
                        current_url,
                        timeout=self.timeout,
                        stream=True
                    )
                    
                    content = get_response.text[:10000]
                    location_from_body = self.extract_location_from_body(content)
                    
                    if location_from_body:
                        result.next_url = location_from_body
                        
                        if not bool(urlparse(location_from_body).netloc):
                            next_url = urljoin(current_url, location_from_body)
                        else:
                            next_url = location_from_body
                            
                        current_url = next_url
                        redirect_count += 1
                        results.append(result)
                        
                        if progress_callback:
                            progress_callback(redirect_count, current_url)
                        continue
                    
                    results.append(result)
                    break
                    
            except requests.exceptions.RequestException as e:
                if not self.stopped:
                    raise e
                break
        
        return results, self.session.session.cookies
    
    def stop(self):
        self.stopped = True

class RedirectAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("URL Redirect Test")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        self.analyzer = None
        self.analysis_thread = None
        self.results = []
        self.cookies = None
        
        self.setup_ui()
        self.setup_styles()
        
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('Title.TLabel', font=('Arial', 14, 'bold'))
        style.configure('Header.TLabel', font=('Arial', 10, 'bold'))
        
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        ttk.Label(main_frame, text="URL Redirect Test", style='Title.TLabel').grid(
            row=0, column=0, columnspan=3, pady=(0, 20)
        )
        
        ttk.Label(main_frame, text="URL:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.url_var = tk.StringVar()
        self.url_entry = ttk.Entry(main_frame, textvariable=self.url_var, width=60)
        self.url_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        self.analyze_button = ttk.Button(main_frame, text="Analyze", command=self.start_analysis)
        self.analyze_button.grid(row=1, column=2, pady=5, padx=(5, 0))
        
        options_frame = ttk.LabelFrame(main_frame, text="Options", padding="10")
        options_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        options_frame.columnconfigure(1, weight=1)
        
        ttk.Label(options_frame, text="Max Redirects:").grid(row=0, column=0, sticky=tk.W)
        self.max_redirects_var = tk.StringVar(value="30")
        ttk.Entry(options_frame, textvariable=self.max_redirects_var, width=10).grid(
            row=0, column=1, sticky=tk.W, padx=(5, 0)
        )
        
        ttk.Label(options_frame, text="Timeout (seconds):").grid(row=0, column=2, sticky=tk.W, padx=(20, 0))
        self.timeout_var = tk.StringVar(value="30")
        ttk.Entry(options_frame, textvariable=self.timeout_var, width=10).grid(
            row=0, column=3, sticky=tk.W, padx=(5, 0)
        )
        
        self.verify_ssl_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Verify SSL", variable=self.verify_ssl_var).grid(
            row=0, column=4, sticky=tk.W, padx=(20, 0)
        )
        
        self.progress_var = tk.StringVar(value="Ready")
        self.progress_label = ttk.Label(main_frame, textvariable=self.progress_var, style='Header.TLabel')
        self.progress_label.grid(row=3, column=0, columnspan=3, pady=10)
        
        self.progress_bar = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress_bar.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        self.stop_button = ttk.Button(main_frame, text="Stop", command=self.stop_analysis, state='disabled')
        self.stop_button.grid(row=5, column=1, pady=5)
        
        results_frame = ttk.LabelFrame(main_frame, text="Results", padding="10")
        results_frame.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(6, weight=1)
        
        self.results_tree = ttk.Treeview(results_frame, columns=('number', 'status', 'url'), show='headings', height=15)
        self.results_tree.heading('number', text='#')
        self.results_tree.heading('status', text='Status')
        self.results_tree.heading('url', text='URL')
        
        self.results_tree.column('number', width=50, anchor='center')
        self.results_tree.column('status', width=80, anchor='center')
        self.results_tree.column('url', width=600)
        
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.results_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=7, column=0, columnspan=3, pady=10)
        
        ttk.Button(buttons_frame, text="Export Results", command=self.export_results).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="View Cookies", command=self.view_cookies).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Clear Results", command=self.clear_results).pack(side=tk.LEFT, padx=5)
        
    def validate_inputs(self) -> bool:
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return False
        
        if not URLValidator.validate_url(url if url.startswith(('http://', 'https://')) else f"https://{url}"):
            messagebox.showerror("Error", "Please enter a valid URL")
            return False
        
        try:
            max_redirects = int(self.max_redirects_var.get())
            if max_redirects < 1 or max_redirects > 100:
                raise ValueError()
        except ValueError:
            messagebox.showerror("Error", "Max redirects must be between 1 and 100")
            return False
        
        try:
            timeout = int(self.timeout_var.get())
            if timeout < 1 or timeout > 300:
                raise ValueError()
        except ValueError:
            messagebox.showerror("Error", "Timeout must be between 1 and 300 seconds")
            return False
        
        return True
    
    def start_analysis(self):
        if not self.validate_inputs():
            return
        
        self.clear_results()
        self.analyze_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.progress_bar.start()
        
        url = URLValidator.sanitize_url(self.url_var.get().strip())
        max_redirects = int(self.max_redirects_var.get())
        timeout = int(self.timeout_var.get())
        verify_ssl = self.verify_ssl_var.get()
        
        self.analyzer = RedirectAnalyzer(max_redirects, timeout, verify_ssl)
        self.analysis_thread = threading.Thread(
            target=self.run_analysis,
            args=(url,),
            daemon=True
        )
        self.analysis_thread.start()
    
    def run_analysis(self, url: str):
        try:
            def progress_callback(count, current_url):
                self.root.after(0, lambda: self.progress_var.set(f"Redirect {count}: {current_url[:50]}..."))
            
            self.root.after(0, lambda: self.progress_var.set("Starting analysis..."))
            results, cookies = self.analyzer.analyze_redirects(url, progress_callback)
            
            self.root.after(0, lambda: self.analysis_complete(results, cookies))
            
        except Exception as e:
            self.root.after(0, lambda: self.analysis_error(str(e)))
    
    def analysis_complete(self, results: List[RedirectResult], cookies):
        self.results = results
        self.cookies = cookies
        
        for result in results:
            self.results_tree.insert('', 'end', values=(
                result.number,
                result.status_code,
                result.url[:100] + "..." if len(result.url) > 100 else result.url
            ))
        
        self.progress_bar.stop()
        self.progress_var.set(f"Analysis complete - {len(results)} steps, {len(results)-1} redirects")
        self.analyze_button.config(state='normal')
        self.stop_button.config(state='disabled')
    
    def analysis_error(self, error_message: str):
        self.progress_bar.stop()
        self.progress_var.set("Analysis failed")
        self.analyze_button.config(state='normal')
        self.stop_button.config(state='disabled')
        messagebox.showerror("Analysis Error", f"Failed to analyze URL: {error_message}")
    
    def stop_analysis(self):
        if self.analyzer:
            self.analyzer.stop()
        self.progress_bar.stop()
        self.progress_var.set("Analysis stopped")
        self.analyze_button.config(state='normal')
        self.stop_button.config(state='disabled')
    
    def clear_results(self):
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.results = []
        self.cookies = None
        self.progress_var.set("Ready")
    
    def export_results(self):
        if not self.results:
            messagebox.showwarning("Warning", "No results to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                if not PathValidator.validate_output_path(os.path.basename(file_path)):
                    messagebox.showerror("Error", "Invalid file path")
                    return
                
                if file_path.endswith('.json'):
                    self.export_json(file_path)
                else:
                    self.export_text(file_path)
                    
                messagebox.showinfo("Success", f"Results exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export results: {str(e)}")
    
    def export_json(self, file_path: str):
        data = {
            "analysis_timestamp": time.time(),
            "original_url": self.results[0].url if self.results else "",
            "final_url": self.results[-1].url if self.results else "",
            "total_redirects": len(self.results) - 1 if self.results else 0,
            "redirects": [asdict(result) for result in self.results],
            "cookies": [
                {
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path
                }
                for cookie in self.cookies
            ] if self.cookies else []
        }
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def export_text(self, file_path: str):
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("=== URL Redirect Analysis Results ===\n\n")
            if self.results:
                f.write(f"Original URL: {self.results[0].url}\n")
                f.write(f"Final URL: {self.results[-1].url}\n")
                f.write(f"Total redirects: {len(self.results) - 1}\n\n")
                
                f.write("=== Redirect Chain ===\n")
                for result in self.results:
                    f.write(f"#{result.number} | Status: {result.status_code} | Time: {result.response_time:.3f}s\n")
                    f.write(f"URL: {result.url}\n")
                    if result.next_url:
                        f.write(f"Next: {result.next_url}\n")
                    f.write("\n")
                
                if self.cookies:
                    f.write("=== Cookies ===\n")
                    for cookie in self.cookies:
                        f.write(f"Domain: {cookie.domain}\n")
                        f.write(f"Name: {cookie.name}\n")
                        f.write(f"Value: {cookie.value}\n")
                        f.write(f"Path: {cookie.path}\n\n")
    
    def view_cookies(self):
        if not self.cookies:
            messagebox.showinfo("Info", "No cookies found")
            return
        
        cookie_window = tk.Toplevel(self.root)
        cookie_window.title("Cookies")
        cookie_window.geometry("600x400")
        
        frame = ttk.Frame(cookie_window, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        tree = ttk.Treeview(frame, columns=('domain', 'name', 'value', 'path'), show='headings')
        tree.heading('domain', text='Domain')
        tree.heading('name', text='Name')
        tree.heading('value', text='Value')
        tree.heading('path', text='Path')
        
        tree.column('domain', width=150)
        tree.column('name', width=120)
        tree.column('value', width=200)
        tree.column('path', width=100)
        
        for cookie in self.cookies:
            tree.insert('', 'end', values=(
                cookie.domain,
                cookie.name,
                cookie.value[:50] + "..." if len(cookie.value) > 50 else cookie.value,
                cookie.path
            ))
        
        scrollbar_v = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        scrollbar_h = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=scrollbar_v.set, xscrollcommand=scrollbar_h.set)
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar_v.pack(side=tk.RIGHT, fill=tk.Y)
        scrollbar_h.pack(side=tk.BOTTOM, fill=tk.X)

def setup_argparse():
    parser = argparse.ArgumentParser(description="Analyze URL redirects with GUI and CLI support")
    parser.add_argument("url", nargs='?', help="The URL to analyze for redirects")
    parser.add_argument("-o", "--output", help="Save results to specified file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show verbose output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    parser.add_argument("--max-redirects", type=int, default=30, help="Maximum number of redirects to follow")
    parser.add_argument("--insecure", action="store_true", help="Allow insecure SSL connections")
    parser.add_argument("--gui", action="store_true", help="Launch GUI mode")
    return parser.parse_args()

def main():
    args = setup_argparse()
    
    if args.gui or not args.url:
        root = tk.Tk()
        app = RedirectAnalyzerGUI(root)
        root.mainloop()
    else:
        try:
            if not URLValidator.validate_url(args.url if args.url.startswith(('http://', 'https://')) else f"https://{args.url}"):
                print("Error: Invalid URL format")
                sys.exit(1)
            
            url = URLValidator.sanitize_url(args.url)
            analyzer = RedirectAnalyzer(args.max_redirects, args.timeout, not args.insecure)
            results, cookies = analyzer.analyze_redirects(url)
            
            print(f"Original URL: {results[0].url}")
            print(f"Final URL: {results[-1].url}")
            print(f"Total redirects: {len(results) - 1}")
            
            if args.verbose:
                print("\nRedirect Chain:")
                for result in results:
                    print(f"#{result.number} | {result.status_code} | {result.url}")
                    if result.next_url:
                        print(f"  → {result.next_url}")
            
            if args.output:
                if not PathValidator.validate_output_path(args.output):
                    print("Error: Invalid output file path")
                    sys.exit(1)
                
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump({
                        "results": [asdict(result) for result in results],
                        "cookies": [{"name": c.name, "value": c.value, "domain": c.domain, "path": c.path} for c in cookies]
                    }, f, indent=2)
                print(f"Results saved to {args.output}")
                
        except Exception as e:
            print(f"Error: {str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    main()
