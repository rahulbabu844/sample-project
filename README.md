# VAPT Project 🔒

A comprehensive Vulnerability Assessment and Penetration Testing (VAPT) toolkit for Web Applications, Mobile Applications, and APIs.

## Primary Features - VAPT Toolkit

### 🎯 Web Application VAPT Scanner
- **SQL Injection Detection**: Tests for SQL injection vulnerabilities in URL parameters
- **Cross-Site Scripting (XSS)**: Detects reflected XSS vulnerabilities
- **Directory Traversal**: Checks for path traversal vulnerabilities
- **Sensitive Files**: Scans for exposed configuration and sensitive files
- **Security Headers**: Checks for missing security headers (X-Frame-Options, CSP, etc.)
- **HTTP Methods**: Identifies dangerous HTTP methods (PUT, DELETE, TRACE)

### 🎯 API VAPT Scanner
- **Authentication Bypass**: Tests endpoints without authentication
- **Rate Limiting**: Checks for missing or weak rate limiting
- **Input Validation**: Tests for SQL injection, XSS, command injection
- **CORS Misconfiguration**: Detects insecure CORS settings
- **Sensitive Data Exposure**: Identifies exposed secrets in API responses

### 🎯 Mobile Application VAPT Scanner
- **APK Analysis**: Analyzes Android APK files for security vulnerabilities
- **Permission Checking**: Reviews dangerous permissions in AndroidManifest.xml
- **Hardcoded Secrets**: Scans for passwords, API keys, tokens in source files
- **SSL Pinning**: Verifies SSL certificate pinning implementation
- **Insecure Storage**: Detects unencrypted data storage usage

### 📊 Report Generator
- Generate comprehensive security reports in JSON, Text, and HTML formats
- Vulnerability categorization by severity (Critical, High, Medium, Low)
- Evidence collection for each vulnerability

## Installation

1. Clone the repository:
```bash
git clone https://github.com/rahulbabu844/sample-project.git
cd sample-project
```

**Note**: This is the VAPT Project repository.

2. No external dependencies required! This project uses only Python standard library.

3. (Optional) Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

## Usage

### Running the VAPT Toolkit

Run the main VAPT interface:
```bash
python vapt_main.py
```

This provides an interactive menu for Web, API, and Mobile VAPT scanning.

### Running Individual VAPT Scanners

You can also run each VAPT scanner independently:

**Web Scanner:**
```bash
python vapt/web_scanner.py
```

**API Scanner:**
```bash
python vapt/api_scanner.py
```

**Mobile Scanner:**
```bash
python vapt/mobile_scanner.py
```

## Tool Examples

### VAPT Toolkit
```python
from vapt.web_scanner import WebVAPTScanner
from vapt.api_scanner import APIVAPTScanner
from vapt.mobile_scanner import MobileVAPTScanner
from vapt.report_generator import VAPTReportGenerator

# Web VAPT
web_scanner = WebVAPTScanner("https://example.com")
web_vulns = web_scanner.scan()

# API VAPT
api_scanner = APIVAPTScanner("https://api.example.com")
api_vulns = api_scanner.scan(['/api/users', '/api/data'])

# Mobile VAPT
mobile_scanner = MobileVAPTScanner()
mobile_vulns = mobile_scanner.scan_apk("app.apk")

# Generate Report
report_gen = VAPTReportGenerator()
report_gen.add_web_vulnerabilities(web_vulns)
report_gen.add_api_vulnerabilities(api_vulns)
report_gen.add_mobile_vulnerabilities(mobile_vulns)
report_gen.generate_html_report("vapt_report.html")
```

**See [vapt/README.md](vapt/README.md) for detailed VAPT documentation.**

## Security Notes

⚠️ **Important Security Considerations:**

**VAPT Testing**: 
- **ONLY test applications and systems you own or have explicit written permission to test**
- Unauthorized security testing is illegal and unethical
- Always obtain proper authorization before conducting VAPT assessments
- Follow responsible disclosure practices for any vulnerabilities found
- Use rate limiting to avoid overwhelming target systems
- Respect the scope of authorized testing

## Project Structure

```
VAPT-Project/
├── vapt_main.py           # VAPT Toolkit main interface
├── vapt/                  # VAPT Toolkit module
│   ├── __init__.py
│   ├── web_scanner.py     # Web application VAPT scanner
│   ├── api_scanner.py     # API VAPT scanner
│   ├── mobile_scanner.py  # Mobile application VAPT scanner
│   ├── report_generator.py # VAPT report generator
│   └── README.md          # Detailed VAPT documentation
├── requirements.txt       # Project dependencies
└── README.md             # This file
```

## Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest new features
- Submit pull requests
- Improve documentation

## License

This project is open source and available for educational purposes.

## Disclaimer

This toolkit is for **educational and authorized security testing purposes only**. Users are responsible for ensuring they have proper authorization before using these tools on any network or system. Unauthorized access to computer systems is illegal.

## Author

Created by rahulbabu844

---

**Stay Secure! 🔒**
