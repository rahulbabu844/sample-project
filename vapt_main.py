"""
VAPT Project - Main Interface
Vulnerability Assessment and Penetration Testing for Web, Mobile, and API
"""

import sys
import os
from vapt.web_scanner import WebVAPTScanner
from vapt.api_scanner import APIVAPTScanner
from vapt.mobile_scanner import MobileVAPTScanner
from vapt.report_generator import VAPTReportGenerator


def print_banner():
    """Print the application banner."""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║         VAPT PROJECT - Vulnerability Assessment              ║
    ║         Web | Mobile | API Security Testing                  ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def web_vapt_menu():
    """Web VAPT scanning menu."""
    print("\n" + "="*60)
    print("WEB APPLICATION VAPT")
    print("="*60)
    
    target_url = input("Enter target URL: ").strip()
    if not target_url:
        print("Error: URL cannot be empty.")
        return
    
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    scanner = WebVAPTScanner(target_url)
    vulnerabilities = scanner.scan()
    
    return vulnerabilities


def api_vapt_menu():
    """API VAPT scanning menu."""
    print("\n" + "="*60)
    print("API VAPT")
    print("="*60)
    
    base_url = input("Enter API base URL: ").strip()
    if not base_url:
        print("Error: Base URL cannot be empty.")
        return []
    
    if not base_url.startswith(('http://', 'https://')):
        base_url = 'https://' + base_url
    
    endpoints_input = input("Enter endpoints (comma-separated, or press Enter for default): ").strip()
    endpoints = None
    if endpoints_input:
        endpoints = [e.strip() for e in endpoints_input.split(',')]
    
    scanner = APIVAPTScanner(base_url)
    vulnerabilities = scanner.scan(endpoints)
    
    return vulnerabilities


def mobile_vapt_menu():
    """Mobile VAPT scanning menu."""
    print("\n" + "="*60)
    print("MOBILE APPLICATION VAPT")
    print("="*60)
    
    apk_path = input("Enter APK file path: ").strip()
    if not apk_path:
        print("Error: APK path cannot be empty.")
        return []
    
    if not os.path.exists(apk_path):
        print(f"Error: APK file not found: {apk_path}")
        return []
    
    scanner = MobileVAPTScanner()
    vulnerabilities = scanner.scan_apk(apk_path)
    
    return vulnerabilities


def generate_report_menu(web_vulns=None, api_vulns=None, mobile_vulns=None):
    """Report generation menu."""
    print("\n" + "="*60)
    print("GENERATE VAPT REPORT")
    print("="*60)
    
    generator = VAPTReportGenerator()
    
    if web_vulns:
        generator.add_web_vulnerabilities(web_vulns)
    if api_vulns:
        generator.add_api_vulnerabilities(api_vulns)
    if mobile_vulns:
        generator.add_mobile_vulnerabilities(mobile_vulns)
    
    print("\nSelect report format:")
    print("1. JSON")
    print("2. Text")
    print("3. HTML")
    print("4. All formats")
    
    choice = input("\nEnter choice: ").strip()
    
    if choice == '1':
        generator.generate_json_report()
    elif choice == '2':
        generator.generate_text_report()
    elif choice == '3':
        generator.generate_html_report()
    elif choice == '4':
        generator.generate_json_report()
        generator.generate_text_report()
        generator.generate_html_report()
    else:
        print("Invalid choice.")


def main():
    """Main application loop."""
    print_banner()
    
    web_vulnerabilities = []
    api_vulnerabilities = []
    mobile_vulnerabilities = []
    
    while True:
        print("\n" + "="*60)
        print("MAIN MENU")
        print("="*60)
        print("1. Web Application VAPT")
        print("2. API VAPT")
        print("3. Mobile Application VAPT")
        print("4. Generate Report")
        print("5. View Current Results")
        print("6. Exit")
        print("="*60)
        
        choice = input("\nSelect an option (1-6): ").strip()
        
        if choice == '1':
            vulns = web_vapt_menu()
            if vulns:
                web_vulnerabilities = vulns
                print(f"\n[+] Found {len(vulns)} web vulnerabilities")
        
        elif choice == '2':
            vulns = api_vapt_menu()
            if vulns:
                api_vulnerabilities = vulns
                print(f"\n[+] Found {len(vulns)} API vulnerabilities")
        
        elif choice == '3':
            vulns = mobile_vapt_menu()
            if vulns:
                mobile_vulnerabilities = vulns
                print(f"\n[+] Found {len(vulns)} mobile vulnerabilities")
        
        elif choice == '4':
            if not (web_vulnerabilities or api_vulnerabilities or mobile_vulnerabilities):
                print("\n[!] No vulnerabilities found yet. Please run scans first.")
            else:
                generate_report_menu(web_vulnerabilities, api_vulnerabilities, mobile_vulnerabilities)
        
        elif choice == '5':
            print("\n" + "="*60)
            print("CURRENT RESULTS")
            print("="*60)
            print(f"Web Vulnerabilities: {len(web_vulnerabilities)}")
            print(f"API Vulnerabilities: {len(api_vulnerabilities)}")
            print(f"Mobile Vulnerabilities: {len(mobile_vulnerabilities)}")
            print(f"Total: {len(web_vulnerabilities) + len(api_vulnerabilities) + len(mobile_vulnerabilities)}")
        
        elif choice == '6':
            print("\nThank you for using VAPT Project!")
            print("Stay secure! 🔒\n")
            sys.exit(0)
        
        else:
            print("\nInvalid choice. Please select 1-6.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user.")
        sys.exit(0)
