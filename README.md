# Features

- Follows and analyzes all HTTP redirects (301, 302, 303, 307, 308)
- Detects JavaScript and meta refresh redirects when in verbose mode
- Captures and displays cookies set during the redirect process

# Installation

- Clone the repository

        git clone https://github.com/f3lipees/url_redirect_test.git

        cd url_redirect_test

# Usage

        python redirecttest.py https://t.co/exemple
        
        
![redirect](https://github.com/user-attachments/assets/43c27522-a13e-4978-8c69-effa3bfbe2bd)


       

# Options
        -o, --output       Save results to specified file
        -v, --verbose      Show verbose output (detect JS/meta redirects)
        --no-color         Disable colored output
        --timeout          Request timeout in seconds (default: 30)
        --max-redirects    Maximum number of redirects to follow (default: 30)
        --insecure         Allow insecure SSL connections
