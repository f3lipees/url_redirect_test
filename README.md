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
        
        
![redirecttest](https://github.com/user-attachments/assets/21d8de7a-6305-42bd-8986-1c64c2a2113b)



       
# Options
        -o, --output       Save results to specified file
        -v, --verbose      Show verbose output (detect JS/meta redirects)
        --no-color         Disable colored output
        --timeout          Request timeout in seconds (default: 30)
        --max-redirects    Maximum number of redirects to follow (default: 30)
        --insecure         Allow insecure SSL connections
