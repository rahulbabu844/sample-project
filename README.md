# VAPT Project 🔒

A comprehensive Vulnerability Assessment and Penetration Testing (VAPT) toolkit for Web Applications, Mobile Applications, and APIs. Includes additional cybersecurity tools for password checking, file integrity monitoring, and network scanning.

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

## Additional Cybersecurity Tools

### 1. Password Strength Checker
- Analyzes password strength based on multiple criteria
- Checks for length, character variety (uppercase, lowercase, numbers, special characters)
- Detects common weak patterns and passwords
- Provides detailed feedback and scoring (0-10 scale)

### 2. Hash Generator & Verifier
- Generate hashes for files and strings
- Supports multiple algorithms: MD5, SHA1, SHA256, SHA512
- Verify file integrity by comparing hashes
- Useful for file integrity checking and data verification

### 3. Port Scanner
- Scan common ports or custom port ranges
- Multi-threaded scanning for faster results
- Identifies common services running on open ports
- Useful for network security assessment

### 4. File Integrity Checker
- Monitor files for unauthorized changes
- Hash-based integrity verification
- Database of monitored files with timestamps
- Batch checking of all monitored files
- Detect file modifications, deletions, and tampering


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

### Running the VAPT Toolkit (Primary)

Run the main VAPT interface:
```bash
python vapt_main.py
```

This provides an interactive menu for Web, API, and Mobile VAPT scanning.

### Running Additional Cybersecurity Tools

Run the cybersecurity tools interface:
```bash
python main.py
```

This will present you with a menu to access password checker, hash tool, port scanner, and file integrity checker.

### Running Individual Tools

You can also run each tool independently:

**Password Checker:**
```bash
python password_checker.py
```

**Hash Tool:**
```bash
python hash_tool.py
```

**Port Scanner:**
```bash
python port_scanner.py
```

**File Integrity Checker:**
```bash
python file_integrity.py
```

**VAPT Toolkit:**
```bash
python vapt_main.py
```

You can also run individual VAPT scanners:
```bash
python vapt/web_scanner.py
python vapt/api_scanner.py
python vapt/mobile_scanner.py
```

## Tool Examples

### Password Strength Checker
```python
from password_checker import check_password_strength

result = check_password_strength("MyP@ssw0rd123!")
print(f"Strength: {result['level']}")
print(f"Score: {result['score']}/10")
```

### Hash Generator
```python
from hash_tool import calculate_hash, calculate_string_hash

# File hash
file_hash = calculate_hash("document.pdf", "sha256")

# String hash
text_hash = calculate_string_hash("Hello World", "sha256")
```

### Port Scanner
```python
from port_scanner import scan_common_ports, scan_port_range

# Scan common ports
scan_common_ports("example.com")

# Scan custom range
scan_port_range("192.168.1.1", 1, 1000)
```

### File Integrity Checker
```python
from file_integrity import FileIntegrityChecker

checker = FileIntegrityChecker()

# Add file to monitor
checker.add_file("important_file.txt")

# Check file integrity
result = checker.check_file("important_file.txt")
print(result['message'])

# Check all monitored files
checker.check_all()
```

### VAPT Toolkit (Primary Focus)
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

1. **Port Scanning**: Only scan systems you own or have explicit permission to scan. Unauthorized port scanning may be illegal.

2. **File Integrity**: The integrity database (`integrity_db.json`) should be stored securely. If compromised, an attacker could modify it to hide file changes.

3. **Password Checking**: This tool checks passwords locally. Never send passwords over unsecured networks.

4. **Hash Algorithms**: 
   - MD5 and SHA1 are considered weak and should not be used for security-critical applications
   - SHA256 and SHA512 are recommended for security purposes

5. **VAPT Testing**: 
   - **ONLY test applications and systems you own or have explicit written permission to test**
   - Unauthorized security testing is illegal and unethical
   - Always obtain proper authorization before conducting VAPT assessments
   - Follow responsible disclosure practices for any vulnerabilities found

## Project Structure

```
VAPT-Project/
├── main.py                 # Cybersecurity tools CLI interface
├── vapt_main.py           # VAPT Toolkit main interface (Primary)
├── password_checker.py     # Password strength analysis
├── hash_tool.py           # Hash generation and verification
├── port_scanner.py        # Network port scanning
├── file_integrity.py      # File integrity monitoring
├── vapt/                  # VAPT Toolkit module
│   ├── __init__.py
│   ├── web_scanner.py     # Web application VAPT scanner
│   ├── api_scanner.py     # API VAPT scanner
│   ├── mobile_scanner.py  # Mobile application VAPT scanner
│   └── report_generator.py # VAPT report generator
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
