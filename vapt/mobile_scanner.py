"""
Mobile Application VAPT Scanner
Scans mobile applications for security vulnerabilities
"""

import os
import json
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path


class MobileVAPTScanner:
    """Mobile Application Vulnerability Assessment and Penetration Testing Scanner."""
    
    def __init__(self, apk_path=None):
        """
        Initialize the mobile scanner.
        
        Args:
            apk_path (str): Path to APK file (for Android)
        """
        self.apk_path = apk_path
        self.vulnerabilities = []
        self.extracted_path = None
        
    def extract_apk(self, apk_path):
        """
        Extract APK file.
        
        Args:
            apk_path (str): Path to APK file
            
        Returns:
            str: Path to extracted directory
        """
        if not os.path.exists(apk_path):
            print(f"Error: APK file not found: {apk_path}")
            return None
        
        extract_dir = apk_path.replace('.apk', '_extracted')
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            print(f"[+] APK extracted to: {extract_dir}")
            return extract_dir
        except Exception as e:
            print(f"Error extracting APK: {e}")
            return None
    
    def analyze_android_manifest(self, manifest_path):
        """
        Analyze AndroidManifest.xml for security issues.
        
        Args:
            manifest_path (str): Path to AndroidManifest.xml
        """
        print("\n[+] Analyzing AndroidManifest.xml...")
        
        if not os.path.exists(manifest_path):
            print("  [-] AndroidManifest.xml not found")
            return
        
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Check for debuggable flag
            application = root.find('application')
            if application is not None:
                debuggable = application.get('{http://schemas.android.com/apk/res/android}debuggable')
                if debuggable == 'true':
                    vuln = {
                        'type': 'Debug Mode Enabled',
                        'severity': 'High',
                        'file': 'AndroidManifest.xml',
                        'evidence': 'android:debuggable="true" is set in production'
                    }
                    self.vulnerabilities.append(vuln)
                    print("  [!] Debug mode is enabled in production")
                
                # Check for backup allowed
                allow_backup = application.get('{http://schemas.android.com/apk/res/android}allowBackup')
                if allow_backup == 'true':
                    vuln = {
                        'type': 'Backup Allowed',
                        'severity': 'Medium',
                        'file': 'AndroidManifest.xml',
                        'evidence': 'android:allowBackup="true" allows data backup'
                    }
                    self.vulnerabilities.append(vuln)
                    print("  [!] Backup is allowed - sensitive data may be exposed")
            
            # Check permissions
            dangerous_permissions = [
                'android.permission.READ_SMS',
                'android.permission.SEND_SMS',
                'android.permission.READ_PHONE_STATE',
                'android.permission.ACCESS_FINE_LOCATION',
                'android.permission.ACCESS_COARSE_LOCATION',
                'android.permission.CAMERA',
                'android.permission.RECORD_AUDIO',
                'android.permission.READ_CONTACTS',
                'android.permission.WRITE_CONTACTS',
                'android.permission.READ_EXTERNAL_STORAGE',
                'android.permission.WRITE_EXTERNAL_STORAGE',
            ]
            
            permissions = root.findall('uses-permission')
            found_permissions = []
            
            for perm in permissions:
                perm_name = perm.get('{http://schemas.android.com/apk/res/android}name')
                if perm_name:
                    found_permissions.append(perm_name)
                    if perm_name in dangerous_permissions:
                        vuln = {
                            'type': 'Dangerous Permission',
                            'severity': 'Medium',
                            'permission': perm_name,
                            'file': 'AndroidManifest.xml',
                            'evidence': f'App requests dangerous permission: {perm_name}'
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"  [!] Dangerous permission requested: {perm_name}")
            
            # Check for exported components
            activities = root.findall('.//activity')
            services = root.findall('.//service')
            receivers = root.findall('.//receiver')
            
            exported_components = []
            
            for component in activities + services + receivers:
                exported = component.get('{http://schemas.android.com/apk/res/android}exported')
                if exported == 'true':
                    component_name = component.get('{http://schemas.android.com/apk/res/android}name', 'Unknown')
                    exported_components.append(component_name)
            
            if exported_components:
                vuln = {
                    'type': 'Exported Components',
                    'severity': 'High',
                    'components': exported_components,
                    'file': 'AndroidManifest.xml',
                    'evidence': f'{len(exported_components)} components are exported'
                }
                self.vulnerabilities.append(vuln)
                print(f"  [!] {len(exported_components)} exported components found")
            
        except Exception as e:
            print(f"Error analyzing manifest: {e}")
    
    def check_hardcoded_secrets(self, extracted_path):
        """
        Check for hardcoded secrets in source files.
        
        Args:
            extracted_path (str): Path to extracted APK directory
        """
        print("\n[+] Checking for hardcoded secrets...")
        
        secret_patterns = [
            (r'password["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Hardcoded Password'),
            (r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Hardcoded API Key'),
            (r'secret["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Hardcoded Secret'),
            (r'token["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Hardcoded Token'),
            (r'[A-Za-z0-9]{32,}', 'Potential Secret Key'),  # Long alphanumeric strings
        ]
        
        import re
        
        for root, dirs, files in os.walk(extracted_path):
            # Skip certain directories
            dirs[:] = [d for d in dirs if d not in ['META-INF', '__MACOSX']]
            
            for file in files:
                if file.endswith(('.smali', '.java', '.xml', '.properties', '.json')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            for pattern, vuln_type in secret_patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    # Skip common false positives
                                    if 'example' in match.group(0).lower() or 'test' in match.group(0).lower():
                                        continue
                                    
                                    vuln = {
                                        'type': vuln_type,
                                        'severity': 'High',
                                        'file': file_path.replace(extracted_path, ''),
                                        'evidence': f'Potential secret found: {match.group(0)[:50]}...'
                                    }
                                    self.vulnerabilities.append(vuln)
                                    print(f"  [!] Potential secret in {file_path}: {match.group(0)[:50]}...")
                                    break
                    except Exception:
                        continue
    
    def check_ssl_pinning(self, extracted_path):
        """
        Check for SSL pinning implementation.
        
        Args:
            extracted_path (str): Path to extracted APK directory
        """
        print("\n[+] Checking SSL pinning implementation...")
        
        ssl_pinning_indicators = [
            'X509TrustManager',
            'CertificatePinner',
            'PinManager',
            'TrustManager',
        ]
        
        found_indicators = []
        
        for root, dirs, files in os.walk(extracted_path):
            for file in files:
                if file.endswith(('.smali', '.java')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            for indicator in ssl_pinning_indicators:
                                if indicator in content:
                                    found_indicators.append(indicator)
                                    break
                    except Exception:
                        continue
        
        if not found_indicators:
            vuln = {
                'type': 'Missing SSL Pinning',
                'severity': 'Medium',
                'evidence': 'No SSL pinning implementation detected'
            }
            self.vulnerabilities.append(vuln)
            print("  [!] SSL pinning not detected - app vulnerable to MITM attacks")
        else:
            print(f"  [+] SSL pinning indicators found: {', '.join(set(found_indicators))}")
    
    def check_insecure_storage(self, extracted_path):
        """
        Check for insecure data storage.
        
        Args:
            extracted_path (str): Path to extracted APK directory
        """
        print("\n[+] Checking for insecure storage...")
        
        insecure_patterns = [
            (r'SharedPreferences', 'SharedPreferences Usage'),
            (r'getSharedPreferences', 'SharedPreferences Usage'),
            (r'SQLiteDatabase', 'SQLite Database'),
            (r'openOrCreateDatabase', 'SQLite Database'),
        ]
        
        import re
        
        for root, dirs, files in os.walk(extracted_path):
            for file in files:
                if file.endswith(('.smali', '.java')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            for pattern, storage_type in insecure_patterns:
                                if re.search(pattern, content):
                                    # Check if encryption is used
                                    if 'encrypt' not in content.lower() and 'cipher' not in content.lower():
                                        vuln = {
                                            'type': 'Insecure Storage',
                                            'severity': 'Medium',
                                            'file': file_path.replace(extracted_path, ''),
                                            'storage_type': storage_type,
                                            'evidence': f'{storage_type} used without encryption'
                                        }
                                        self.vulnerabilities.append(vuln)
                                        print(f"  [!] Insecure storage detected: {storage_type}")
                                        break
                    except Exception:
                        continue
    
    def scan_apk(self, apk_path):
        """
        Scan an Android APK file.
        
        Args:
            apk_path (str): Path to APK file
        """
        print(f"\n{'='*60}")
        print(f"Mobile VAPT Scan: {apk_path}")
        print(f"{'='*60}")
        
        print("\n[+] Starting APK scan...")
        
        extracted_path = self.extract_apk(apk_path)
        if not extracted_path:
            return []
        
        self.extracted_path = extracted_path
        
        # Find AndroidManifest.xml
        manifest_paths = [
            os.path.join(extracted_path, 'AndroidManifest.xml'),
            os.path.join(extracted_path, 'AndroidManifest.xml'),
        ]
        
        # Also check in subdirectories
        for root, dirs, files in os.walk(extracted_path):
            if 'AndroidManifest.xml' in files:
                manifest_paths.append(os.path.join(root, 'AndroidManifest.xml'))
        
        manifest_found = False
        for manifest_path in manifest_paths:
            if os.path.exists(manifest_path):
                self.analyze_android_manifest(manifest_path)
                manifest_found = True
                break
        
        if not manifest_found:
            print("  [-] AndroidManifest.xml not found - may need to decode")
        
        self.check_hardcoded_secrets(extracted_path)
        self.check_ssl_pinning(extracted_path)
        self.check_insecure_storage(extracted_path)
        
        print(f"\n{'='*60}")
        print(f"Scan Complete!")
        print(f"Total vulnerabilities found: {len(self.vulnerabilities)}")
        print(f"{'='*60}\n")
        
        return self.vulnerabilities
    
    def generate_permission_report(self, manifest_path):
        """
        Generate a permission analysis report.
        
        Args:
            manifest_path (str): Path to AndroidManifest.xml
        """
        if not os.path.exists(manifest_path):
            return None
        
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            permissions = []
            for perm in root.findall('uses-permission'):
                perm_name = perm.get('{http://schemas.android.com/apk/res/android}name', '')
                if perm_name:
                    permissions.append(perm_name)
            
            return {
                'total_permissions': len(permissions),
                'permissions': permissions
            }
        except Exception as e:
            print(f"Error generating permission report: {e}")
            return None


if __name__ == "__main__":
    print("Mobile Application VAPT Scanner")
    print("-" * 60)
    
    apk_path = input("Enter APK file path: ").strip()
    
    if apk_path and os.path.exists(apk_path):
        scanner = MobileVAPTScanner()
        vulnerabilities = scanner.scan_apk(apk_path)
        
        if vulnerabilities:
            print("\nVulnerabilities Found:")
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"\n{i}. {vuln['type']} ({vuln['severity']})")
                print(f"   Evidence: {vuln['evidence']}")
    else:
        print("Error: APK file not found.")
