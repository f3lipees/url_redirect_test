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
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box
from urllib.parse import urljoin, urlparse

def setup_argparse():
    parser = argparse.ArgumentParser(description="Analyze URL redirects with detailed tracking")
    parser.add_argument("url", help="The URL to analyze for redirects")
    parser.add_argument("-o", "--output", help="Save results to specified file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show verbose output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    parser.add_argument("--max-redirects", type=int, default=30, help="Maximum number of redirects to follow")
    parser.add_argument("--insecure", action="store_true", help="Allow insecure SSL connections")
    return parser.parse_args()

def get_temp_file():
    temp_dir = tempfile.gettempdir()
    cookie_file = os.path.join(temp_dir, f"redirect_cookies_{uuid.uuid4().hex}.txt")
    return cookie_file

def extract_location_from_body(body):
    location = None
    js_redirect = re.search(r"location\.href\s*=\s*[\"']([^\"']+)[\"']", body)
    meta_redirect = re.search(r"<meta\s+http-equiv=[\"']refresh[\"'][^>]*content=[\"'][^\"']*url=([^\"']+)[\"']", body, re.IGNORECASE)
    
    if js_redirect:
        location = js_redirect.group(1)
    elif meta_redirect:
        location = meta_redirect.group(1)
        
    return location

def analyze_redirects(url, args, console):
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'DNT': '1',
        'Sec-GPC': '1'
    })
    
    verify_ssl = not args.insecure
    cookie_file = get_temp_file()
    redirect_count = 0
    current_url = url
    results = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]Processing redirects..."),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("", total=None)
        
        while redirect_count < args.max_redirects:
            try:
                response = session.head(
                    current_url, 
                    allow_redirects=False, 
                    timeout=args.timeout,
                    verify=verify_ssl
                )
                
                result = {
                    "number": redirect_count + 1,
                    "url": current_url,
                    "status_code": response.status_code,
                    "next_url": None
                }
                
                if 300 <= response.status_code < 400 and 'location' in response.headers:
                    next_url = response.headers['location']
                    result["next_url"] = next_url
                    
                    if not bool(urlparse(next_url).netloc):
                        next_url = urljoin(current_url, next_url)
                    
                    current_url = next_url
                    redirect_count += 1
                    results.append(result)
                else:
                    if args.verbose:
                        response = session.get(
                            current_url,
                            timeout=args.timeout,
                            verify=verify_ssl
                        )
                        
                        location_from_body = extract_location_from_body(response.text)
                        
                        if location_from_body:
                            result["next_url"] = location_from_body
                            
                            if not bool(urlparse(location_from_body).netloc):
                                next_url = urljoin(current_url, location_from_body)
                            else:
                                next_url = location_from_body
                                
                            current_url = next_url
                            redirect_count += 1
                            results.append(result)
                            continue
                    
                    results.append(result)
                    break
                    
            except requests.exceptions.RequestException as e:
                console.print(f"[bold red]Error: {str(e)}[/]")
                break
    
    return results, session.cookies

def display_results(results, cookies, args, console):
    console.print()
    console.print(Panel(
        f"[bold]Redirect Analysis Complete[/]\n"
        f"[cyan]Total redirects:[/] {len(results) - 1}\n"
        f"[cyan]Original URL:[/] {results[0]['url']}\n"
        f"[cyan]Final destination:[/] {results[-1]['url']}",
        title="Summary",
        box=box.ROUNDED
    ))
    
    console.print()
    
    if len(results) > 1:
        table = Table(title="Redirect Chain", box=box.SIMPLE_HEAD)
        table.add_column("#", style="cyan", no_wrap=True)
        table.add_column("Status", style="green")
        table.add_column("URL", style="blue")
        
        for result in results:
            table.add_row(
                str(result["number"]),
                str(result["status_code"]),
                textwrap.shorten(result["url"], width=80, placeholder="...")
            )
        
        console.print(table)
    
    console.print()
    
    if cookies:
        cookie_table = Table(title="Cookies Set", box=box.SIMPLE_HEAD)
        cookie_table.add_column("Domain", style="cyan")
        cookie_table.add_column("Name", style="green")
        cookie_table.add_column("Value", style="blue")
        cookie_table.add_column("Path", style="magenta")
        
        for cookie in cookies:
            cookie_table.add_row(
                cookie.domain,
                cookie.name,
                textwrap.shorten(cookie.value, width=30, placeholder="..."),
                cookie.path
            )
        
        console.print(cookie_table)
    
    if args.output:
        save_results(results, cookies, args.output)
        console.print(f"\n[green]Results saved to {args.output}[/]")

def save_results(results, cookies, output_file):
    if '../' in output_file or '..\\' in output_file:
        raise Exception('Invalid file path')
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=== Redirect Analysis Results ===\n\n")
        f.write(f"Original URL: {results[0]['url']}\n")
        f.write(f"Final destination: {results[-1]['url']}\n")
        f.write(f"Total redirects: {len(results) - 1}\n\n")
        
        f.write("=== Redirect Chain ===\n\n")
        for result in results:
            f.write(f"#{result['number']} | {result['status_code']} | {result['url']}\n")
            if result['next_url']:
                f.write(f"  → {result['next_url']}\n")
        
        f.write("\n=== Cookies ===\n\n")
        for cookie in cookies:
            f.write(f"Domain: {cookie.domain}, Name: {cookie.name}, Path: {cookie.path}\n")
            f.write(f"Value: {cookie.value}\n\n")

def main():
    args = setup_argparse()
    
    console = Console(color_system="auto" if not args.no_color else None)
    
    try:
        if not args.url.startswith(('http://', 'https://')):
            args.url = 'http://' + args.url
            
        results, cookies = analyze_redirects(args.url, args, console)
        display_results(results, cookies, args, console)
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Process interrupted by user[/]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Error: {str(e)}[/]")
        if args.verbose:
            console.print_exception()
        sys.exit(1)

if __name__ == "__main__":
    main()
