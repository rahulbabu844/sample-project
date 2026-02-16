"""
Web Application VAPT Scanner
Scans web applications for common vulnerabilities
"""

import re
import urllib.parse
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import ssl
import time


class WebVAPTScanner:
    """Web Application Vulnerability Assessment and Penetration Testing Scanner."""
    
    def __init__(self, target_url, timeout=10):
        """
        Initialize the web scanner.
        
        Args:
            target_url (str): Target URL to scan
            timeout (int): Request timeout in seconds
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.vulnerabilities = []
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    def _make_request(self, url, method='GET', data=None, headers=None):
        """
        Make HTTP request to target.
        
        Args:
            url (str): URL to request
            method (str): HTTP method
            data (bytes): Request data
            headers (dict): Request headers
            
        Returns:
            tuple: (response_code, response_body, response_headers)
        """
        try:
            req = Request(url, data=data, headers=headers or {})
            req.get_method = lambda: method
            
            with urlopen(req, timeout=self.timeout, context=self.ssl_context) as response:
                return response.getcode(), response.read().decode('utf-8', errors='ignore'), dict(response.headers)
        except HTTPError as e:
            return e.code, e.read().decode('utf-8', errors='ignore'), dict(e.headers)
        except URLError as e:
            return None, str(e), {}
        except Exception as e:
            return None, str(e), {}
    
    def check_sql_injection(self, params=None):
        """
        Check for SQL injection vulnerabilities.
        
        Args:
            params (dict): URL parameters to test
        """
        print("\n[+] Checking for SQL Injection vulnerabilities...")
        
        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "1' UNION SELECT NULL--",
            "' OR 1=1--",
        ]
        
        test_params = params or {'id': '1', 'user': 'admin'}
        
        for param_name, param_value in test_params.items():
            for payload in sql_payloads:
                test_value = param_value + payload
                test_url = f"{self.target_url}?{param_name}={urllib.parse.quote(test_value)}"
                
                code, body, headers = self._make_request(test_url)
                
                if body:
                    error_patterns = [
                        r"mysql_fetch",
                        r"PostgreSQL.*ERROR",
                        r"Warning.*\Wmysql_",
                        r"valid MySQL result",
                        r"MySqlClient\.",
                        r"SQL syntax.*MySQL",
                        r"Warning.*\Wpg_",
                        r"PostgreSQL query failed",
                        r"Warning.*\Woci_",
                        r"Warning.*\Wodbc_",
                        r"Microsoft Access.*Driver",
                        r"ODBC SQL Server Driver",
                        r"SQLServer JDBC Driver",
                        r"SQLException",
                        r"SQLite.*error",
                    ]
                    
                    for pattern in error_patterns:
                        if re.search(pattern, body, re.IGNORECASE):
                            vuln = {
                                'type': 'SQL Injection',
                                'severity': 'High',
                                'parameter': param_name,
                                'payload': payload,
                                'url': test_url,
                                'evidence': f"Database error pattern detected: {pattern}"
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"  [!] Potential SQL Injection found in parameter: {param_name}")
                            print(f"      Payload: {payload}")
                            break
                
                time.sleep(0.5)  # Rate limiting
    
    def check_xss(self, params=None):
        """
        Check for Cross-Site Scripting (XSS) vulnerabilities.
        
        Args:
            params (dict): URL parameters to test
        """
        print("\n[+] Checking for XSS vulnerabilities...")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
        ]
        
        test_params = params or {'q': 'test', 'search': 'test', 'name': 'test'}
        
        for param_name, param_value in test_params.items():
            for payload in xss_payloads:
                test_value = payload
                test_url = f"{self.target_url}?{param_name}={urllib.parse.quote(test_value)}"
                
                code, body, headers = self._make_request(test_url)
                
                if body and payload in body:
                    # Check if payload is reflected without encoding
                    if payload in body or payload.replace("'", "&#39;") in body:
                        vuln = {
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'Medium',
                            'parameter': param_name,
                            'payload': payload,
                            'url': test_url,
                            'evidence': 'Payload reflected in response without proper encoding'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"  [!] Potential XSS found in parameter: {param_name}")
                        print(f"      Payload: {payload[:50]}...")
                        break
                
                time.sleep(0.5)
    
    def check_directory_traversal(self):
        """Check for directory traversal vulnerabilities."""
        print("\n[+] Checking for Directory Traversal vulnerabilities...")
        
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]
        
        test_params = ['file', 'path', 'page', 'include', 'doc']
        
        for param in test_params:
            for payload in traversal_payloads:
                test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                
                code, body, headers = self._make_request(test_url)
                
                if body:
                    if 'root:' in body or '[boot loader]' in body.lower():
                        vuln = {
                            'type': 'Directory Traversal',
                            'severity': 'High',
                            'parameter': param,
                            'payload': payload,
                            'url': test_url,
                            'evidence': 'System file content detected in response'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"  [!] Potential Directory Traversal found in parameter: {param}")
                        break
                
                time.sleep(0.5)
    
    def check_sensitive_files(self):
        """Check for exposed sensitive files."""
        print("\n[+] Checking for exposed sensitive files...")
        
        sensitive_files = [
            '/.env',
            '/config.php',
            '/.git/config',
            '/.svn/entries',
            '/web.config',
            '/phpinfo.php',
            '/.htaccess',
            '/robots.txt',
            '/sitemap.xml',
            '/backup.sql',
            '/database.sql',
        ]
        
        for file_path in sensitive_files:
            test_url = self.target_url + file_path
            code, body, headers = self._make_request(test_url)
            
            if code == 200:
                # Check for sensitive content
                sensitive_patterns = [
                    r'DB_PASSWORD',
                    r'API_KEY',
                    r'SECRET',
                    r'password.*=',
                    r'\[core\]',  # .git/config
                ]
                
                for pattern in sensitive_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        vuln = {
                            'type': 'Exposed Sensitive File',
                            'severity': 'High',
                            'file': file_path,
                            'url': test_url,
                            'evidence': f'Sensitive pattern detected: {pattern}'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"  [!] Sensitive file exposed: {file_path}")
                        break
            
            time.sleep(0.3)
    
    def check_http_methods(self):
        """Check for insecure HTTP methods."""
        print("\n[+] Checking HTTP methods...")
        
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE', 'HEAD']
        allowed_methods = []
        
        for method in methods:
            code, body, headers = self._make_request(self.target_url, method=method)
            if code and code != 405:  # 405 Method Not Allowed
                allowed_methods.append(method)
        
        dangerous_methods = ['PUT', 'DELETE', 'TRACE']
        for method in dangerous_methods:
            if method in allowed_methods:
                vuln = {
                    'type': 'Insecure HTTP Method',
                    'severity': 'Medium',
                    'method': method,
                    'url': self.target_url,
                    'evidence': f'Dangerous HTTP method {method} is enabled'
                }
                self.vulnerabilities.append(vuln)
                print(f"  [!] Dangerous HTTP method enabled: {method}")
    
    def check_security_headers(self):
        """Check for missing security headers."""
        print("\n[+] Checking security headers...")
        
        code, body, headers = self._make_request(self.target_url)
        
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'X-XSS-Protection': '1',
            'Strict-Transport-Security': None,
            'Content-Security-Policy': None,
        }
        
        for header, expected_value in security_headers.items():
            header_value = headers.get(header, '')
            
            if not header_value:
                vuln = {
                    'type': 'Missing Security Header',
                    'severity': 'Low',
                    'header': header,
                    'url': self.target_url,
                    'evidence': f'Security header {header} is missing'
                }
                self.vulnerabilities.append(vuln)
                print(f"  [!] Missing security header: {header}")
            elif expected_value and expected_value not in header_value:
                if isinstance(expected_value, list):
                    if header_value not in expected_value:
                        print(f"  [-] Security header {header} has non-optimal value: {header_value}")
    
    def scan(self):
        """Run all vulnerability scans."""
        print(f"\n{'='*60}")
        print(f"Web VAPT Scan: {self.target_url}")
        print(f"{'='*60}")
        
        print("\n[+] Starting scan...")
        
        self.check_security_headers()
        self.check_http_methods()
        self.check_sensitive_files()
        self.check_sql_injection()
        self.check_xss()
        self.check_directory_traversal()
        
        print(f"\n{'='*60}")
        print(f"Scan Complete!")
        print(f"Total vulnerabilities found: {len(self.vulnerabilities)}")
        print(f"{'='*60}\n")
        
        return self.vulnerabilities


if __name__ == "__main__":
    print("Web Application VAPT Scanner")
    print("-" * 60)
    
    target = input("Enter target URL: ").strip()
    if target:
        scanner = WebVAPTScanner(target)
        vulnerabilities = scanner.scan()
        
        if vulnerabilities:
            print("\nVulnerabilities Found:")
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"\n{i}. {vuln['type']} ({vuln['severity']})")
                print(f"   URL: {vuln.get('url', vuln.get('file', 'N/A'))}")
                print(f"   Evidence: {vuln['evidence']}")
