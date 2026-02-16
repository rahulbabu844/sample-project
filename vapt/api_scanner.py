"""
API VAPT Scanner
Scans REST APIs for security vulnerabilities
"""

import json
import time
import hashlib
import hmac
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import ssl


class APIVAPTScanner:
    """API Vulnerability Assessment and Penetration Testing Scanner."""
    
    def __init__(self, base_url, timeout=10):
        """
        Initialize the API scanner.
        
        Args:
            base_url (str): Base URL of the API
            timeout (int): Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.vulnerabilities = []
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        self.endpoints = []
        
    def _make_request(self, url, method='GET', headers=None, data=None):
        """
        Make HTTP request to API.
        
        Args:
            url (str): API endpoint URL
            method (str): HTTP method
            headers (dict): Request headers
            data (bytes): Request body
            
        Returns:
            tuple: (status_code, response_body, response_headers)
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
    
    def check_authentication_bypass(self, endpoint, auth_header=None):
        """
        Check for authentication bypass vulnerabilities.
        
        Args:
            endpoint (str): API endpoint to test
            auth_header (dict): Authentication headers
        """
        print(f"\n[+] Checking authentication bypass for {endpoint}...")
        
        test_url = self.base_url + endpoint
        
        # Test without authentication
        code, body, headers = self._make_request(test_url)
        
        if code == 200:
            vuln = {
                'type': 'Authentication Bypass',
                'severity': 'Critical',
                'endpoint': endpoint,
                'url': test_url,
                'evidence': 'Endpoint accessible without authentication'
            }
            self.vulnerabilities.append(vuln)
            print(f"  [!] Endpoint accessible without authentication: {endpoint}")
        
        # Test with invalid/empty token
        invalid_auth_headers = [
            {'Authorization': ''},
            {'Authorization': 'Bearer '},
            {'Authorization': 'Bearer invalid_token'},
            {'X-API-Key': ''},
            {'X-API-Key': 'invalid'},
        ]
        
        for invalid_header in invalid_auth_headers:
            code, body, headers = self._make_request(test_url, headers=invalid_header)
            if code == 200:
                vuln = {
                    'type': 'Weak Authentication',
                    'severity': 'High',
                    'endpoint': endpoint,
                    'url': test_url,
                    'evidence': f'Endpoint accessible with invalid auth: {invalid_header}'
                }
                self.vulnerabilities.append(vuln)
                print(f"  [!] Weak authentication detected: {endpoint}")
                break
    
    def check_rate_limiting(self, endpoint):
        """
        Check for missing or weak rate limiting.
        
        Args:
            endpoint (str): API endpoint to test
        """
        print(f"\n[+] Checking rate limiting for {endpoint}...")
        
        test_url = self.base_url + endpoint
        requests_sent = 0
        rate_limit_hit = False
        
        # Send rapid requests
        for i in range(100):
            code, body, headers = self._make_request(test_url)
            requests_sent += 1
            
            if code == 429:  # Too Many Requests
                rate_limit_hit = True
                break
            
            if code and code >= 500:
                break
            
            time.sleep(0.1)
        
        if not rate_limit_hit and requests_sent >= 50:
            vuln = {
                'type': 'Missing Rate Limiting',
                'severity': 'Medium',
                'endpoint': endpoint,
                'url': test_url,
                'evidence': f'No rate limiting detected after {requests_sent} requests'
            }
            self.vulnerabilities.append(vuln)
            print(f"  [!] Missing rate limiting: {endpoint}")
    
    def check_input_validation(self, endpoint, method='POST'):
        """
        Check for input validation vulnerabilities.
        
        Args:
            endpoint (str): API endpoint to test
            method (str): HTTP method
        """
        print(f"\n[+] Checking input validation for {endpoint}...")
        
        test_url = self.base_url + endpoint
        
        # SQL Injection payloads
        sql_payloads = ["' OR '1'='1", "1' UNION SELECT NULL--"]
        
        # XSS payloads
        xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]
        
        # Command injection payloads
        cmd_payloads = ["; ls", "| whoami", "&& id", "`whoami`"]
        
        # Path traversal
        path_payloads = ["../../../etc/passwd", "..\\..\\windows\\system32"]
        
        # Test payloads
        test_data = {
            'id': 1,
            'name': 'test',
            'email': 'test@test.com',
            'file': 'test.txt'
        }
        
        all_payloads = sql_payloads + xss_payloads + cmd_payloads + path_payloads
        
        for payload in all_payloads[:5]:  # Limit to avoid too many requests
            test_payload = {k: payload for k in test_data.keys()}
            json_data = json.dumps(test_payload).encode('utf-8')
            
            headers = {'Content-Type': 'application/json'}
            code, body, headers_resp = self._make_request(test_url, method=method, 
                                                          headers=headers, data=json_data)
            
            if body and payload in body:
                vuln = {
                    'type': 'Input Validation Bypass',
                    'severity': 'High',
                    'endpoint': endpoint,
                    'payload': payload,
                    'url': test_url,
                    'evidence': 'Payload reflected in response without validation'
                }
                self.vulnerabilities.append(vuln)
                print(f"  [!] Input validation issue: {endpoint}")
                break
            
            time.sleep(0.3)
    
    def check_cors_misconfiguration(self, endpoint):
        """
        Check for CORS misconfiguration.
        
        Args:
            endpoint (str): API endpoint to test
        """
        print(f"\n[+] Checking CORS configuration for {endpoint}...")
        
        test_url = self.base_url + endpoint
        
        # Test with Origin header
        headers = {
            'Origin': 'https://evil.com',
            'Access-Control-Request-Method': 'POST'
        }
        
        code, body, headers_resp = self._make_request(test_url, headers=headers)
        
        cors_header = headers_resp.get('Access-Control-Allow-Origin', '')
        cors_credentials = headers_resp.get('Access-Control-Allow-Credentials', '')
        
        if cors_header == '*':
            vuln = {
                'type': 'CORS Misconfiguration',
                'severity': 'Medium',
                'endpoint': endpoint,
                'url': test_url,
                'evidence': 'CORS allows all origins (*)'
            }
            self.vulnerabilities.append(vuln)
            print(f"  [!] CORS allows all origins: {endpoint}")
        elif cors_header and cors_credentials.lower() == 'true':
            vuln = {
                'type': 'CORS Misconfiguration',
                'severity': 'Medium',
                'endpoint': endpoint,
                'url': test_url,
                'evidence': 'CORS allows credentials with wildcard origin'
            }
            self.vulnerabilities.append(vuln)
            print(f"  [!] CORS credentials issue: {endpoint}")
    
    def check_sensitive_data_exposure(self, endpoint):
        """
        Check for sensitive data exposure in responses.
        
        Args:
            endpoint (str): API endpoint to test
        """
        print(f"\n[+] Checking for sensitive data exposure in {endpoint}...")
        
        test_url = self.base_url + endpoint
        code, body, headers = self._make_request(test_url)
        
        if body:
            sensitive_patterns = [
                r'password["\']?\s*[:=]\s*["\']?[^"\']+',
                r'api[_-]?key["\']?\s*[:=]\s*["\']?[^"\']+',
                r'secret["\']?\s*[:=]\s*["\']?[^"\']+',
                r'token["\']?\s*[:=]\s*["\']?[^"\']+',
                r'credit[_-]?card',
                r'[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}',  # Credit card
                r'[0-9]{3}-[0-9]{2}-[0-9]{4}',  # SSN
            ]
            
            import re
            for pattern in sensitive_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    vuln = {
                        'type': 'Sensitive Data Exposure',
                        'severity': 'High',
                        'endpoint': endpoint,
                        'url': test_url,
                        'evidence': f'Sensitive data pattern detected: {pattern}'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"  [!] Sensitive data exposed: {endpoint}")
                    break
    
    def check_http_methods(self, endpoint):
        """Check for insecure HTTP methods."""
        print(f"\n[+] Checking HTTP methods for {endpoint}...")
        
        test_url = self.base_url + endpoint
        dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE']
        
        for method in dangerous_methods:
            code, body, headers = self._make_request(test_url, method=method)
            if code and code not in [405, 501]:  # Not Method Not Allowed
                vuln = {
                    'type': 'Insecure HTTP Method',
                    'severity': 'Medium',
                    'endpoint': endpoint,
                    'method': method,
                    'url': test_url,
                    'evidence': f'Dangerous HTTP method {method} is enabled'
                }
                self.vulnerabilities.append(vuln)
                print(f"  [!] Dangerous HTTP method enabled: {method} on {endpoint}")
    
    def scan_endpoint(self, endpoint, methods=['GET', 'POST']):
        """
        Scan a single API endpoint.
        
        Args:
            endpoint (str): API endpoint path
            methods (list): HTTP methods to test
        """
        print(f"\n{'='*60}")
        print(f"Scanning endpoint: {endpoint}")
        print(f"{'='*60}")
        
        for method in methods:
            test_url = self.base_url + endpoint
            
            # Basic checks
            self.check_http_methods(endpoint)
            self.check_authentication_bypass(endpoint)
            self.check_cors_misconfiguration(endpoint)
            self.check_sensitive_data_exposure(endpoint)
            
            if method in ['POST', 'PUT', 'PATCH']:
                self.check_input_validation(endpoint, method)
            
            self.check_rate_limiting(endpoint)
    
    def scan(self, endpoints=None):
        """
        Run vulnerability scan on API endpoints.
        
        Args:
            endpoints (list): List of endpoints to scan
        """
        if not endpoints:
            endpoints = ['/api/users', '/api/data', '/api/v1/users', '/users', '/api']
        
        print(f"\n{'='*60}")
        print(f"API VAPT Scan: {self.base_url}")
        print(f"{'='*60}")
        
        print("\n[+] Starting scan...")
        
        for endpoint in endpoints:
            self.scan_endpoint(endpoint)
            time.sleep(1)
        
        print(f"\n{'='*60}")
        print(f"Scan Complete!")
        print(f"Total vulnerabilities found: {len(self.vulnerabilities)}")
        print(f"{'='*60}\n")
        
        return self.vulnerabilities


if __name__ == "__main__":
    print("API VAPT Scanner")
    print("-" * 60)
    
    base_url = input("Enter API base URL: ").strip()
    endpoints_input = input("Enter endpoints (comma-separated, or press Enter for default): ").strip()
    
    if base_url:
        endpoints = [e.strip() for e in endpoints_input.split(',')] if endpoints_input else None
        
        scanner = APIVAPTScanner(base_url)
        vulnerabilities = scanner.scan(endpoints)
        
        if vulnerabilities:
            print("\nVulnerabilities Found:")
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"\n{i}. {vuln['type']} ({vuln['severity']})")
                print(f"   Endpoint: {vuln.get('endpoint', 'N/A')}")
                print(f"   Evidence: {vuln['evidence']}")
