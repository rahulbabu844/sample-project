# VAPT Project - Vulnerability Assessment and Penetration Testing

A comprehensive security testing toolkit for Web Applications, APIs, and Mobile Applications.

## Overview

The VAPT Toolkit provides automated security scanning capabilities for:
- **Web Applications**: SQL injection, XSS, CSRF, directory traversal, and more
- **REST APIs**: Authentication bypass, rate limiting, input validation, CORS issues
- **Mobile Applications**: APK analysis, permission checking, hardcoded secrets detection

## Features

### Web VAPT Scanner (`web_scanner.py`)

Scans web applications for common vulnerabilities:

- **SQL Injection**: Tests for SQL injection vulnerabilities in URL parameters
- **Cross-Site Scripting (XSS)**: Detects reflected XSS vulnerabilities
- **Directory Traversal**: Checks for path traversal vulnerabilities
- **Sensitive Files**: Scans for exposed configuration and sensitive files
- **HTTP Methods**: Identifies dangerous HTTP methods (PUT, DELETE, TRACE)
- **Security Headers**: Checks for missing security headers (X-Frame-Options, CSP, etc.)

**Usage:**
```python
from vapt.web_scanner import WebVAPTScanner

scanner = WebVAPTScanner("https://example.com")
vulnerabilities = scanner.scan()
```

### API VAPT Scanner (`api_scanner.py`)

Scans REST APIs for security issues:

- **Authentication Bypass**: Tests endpoints without authentication
- **Rate Limiting**: Checks for missing or weak rate limiting
- **Input Validation**: Tests for SQL injection, XSS, command injection
- **CORS Misconfiguration**: Detects insecure CORS settings
- **Sensitive Data Exposure**: Identifies exposed secrets in API responses
- **HTTP Methods**: Checks for insecure HTTP methods

**Usage:**
```python
from vapt.api_scanner import APIVAPTScanner

scanner = APIVAPTScanner("https://api.example.com")
vulnerabilities = scanner.scan(['/api/users', '/api/data'])
```

### Mobile VAPT Scanner (`mobile_scanner.py`)

Analyzes Android APK files for security vulnerabilities:

- **AndroidManifest Analysis**: Checks for debug mode, backup settings, dangerous permissions
- **Hardcoded Secrets**: Scans for passwords, API keys, tokens in source files
- **SSL Pinning**: Verifies SSL certificate pinning implementation
- **Insecure Storage**: Detects unencrypted data storage usage
- **Exported Components**: Identifies exported activities, services, receivers

**Usage:**
```python
from vapt.mobile_scanner import MobileVAPTScanner

scanner = MobileVAPTScanner()
vulnerabilities = scanner.scan_apk("app.apk")
```

### Report Generator (`report_generator.py`)

Generates comprehensive security assessment reports in multiple formats:

- **JSON Report**: Machine-readable format for integration
- **Text Report**: Human-readable text format
- **HTML Report**: Formatted HTML report with styling

**Usage:**
```python
from vapt.report_generator import VAPTReportGenerator

generator = VAPTReportGenerator()
generator.add_web_vulnerabilities(web_vulns)
generator.add_api_vulnerabilities(api_vulns)
generator.add_mobile_vulnerabilities(mobile_vulns)

generator.generate_json_report("report.json")
generator.generate_text_report("report.txt")
generator.generate_html_report("report.html")
```

## Quick Start

### Running the Main Interface

```bash
python vapt_main.py
```

This provides an interactive menu to:
1. Run Web VAPT scans
2. Run API VAPT scans
3. Run Mobile VAPT scans
4. Generate comprehensive reports
5. View current scan results

### Running Individual Scanners

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

## Vulnerability Severity Levels

- **Critical**: Immediate security risk requiring urgent attention
- **High**: Significant security risk that should be addressed promptly
- **Medium**: Moderate security risk that should be addressed
- **Low**: Minor security issue or best practice recommendation

## Example Workflow

```python
from vapt.web_scanner import WebVAPTScanner
from vapt.api_scanner import APIVAPTScanner
from vapt.report_generator import VAPTReportGenerator

# 1. Scan web application
web_scanner = WebVAPTScanner("https://example.com")
web_vulns = web_scanner.scan()

# 2. Scan API
api_scanner = APIVAPTScanner("https://api.example.com")
api_vulns = api_scanner.scan(['/api/users', '/api/data'])

# 3. Generate comprehensive report
report = VAPTReportGenerator()
report.add_web_vulnerabilities(web_vulns)
report.add_api_vulnerabilities(api_vulns)
report.generate_html_report("security_report.html")
```

## Security Testing Best Practices

1. **Authorization**: Always obtain written permission before testing
2. **Scope**: Clearly define the scope of testing
3. **Documentation**: Document all findings with evidence
4. **Responsible Disclosure**: Follow responsible disclosure practices
5. **Rate Limiting**: Use rate limiting to avoid overwhelming target systems
6. **Backup**: Always backup data before testing in production environments

## Limitations

- This toolkit performs basic automated scans and may not detect all vulnerabilities
- Manual testing and code review are still essential
- Some vulnerabilities require deeper analysis and context
- False positives are possible - always verify findings manually

## Legal and Ethical Considerations

⚠️ **CRITICAL**: 

- **ONLY test applications and systems you own or have explicit written permission to test**
- Unauthorized security testing is **illegal** and **unethical**
- Always obtain proper authorization before conducting VAPT assessments
- Follow responsible disclosure practices for any vulnerabilities found
- Respect rate limits and do not cause denial of service
- Do not access or modify data without authorization

## Contributing

Contributions are welcome! Areas for improvement:
- Additional vulnerability checks
- Better false positive reduction
- Support for more file formats
- Enhanced reporting features
- Performance optimizations

## License

This toolkit is for educational and authorized security testing purposes only.

---

**Remember: With great power comes great responsibility. Use this toolkit ethically and legally! 🔒**
