"""
VAPT Project - Cybersecurity Tools Interface
Additional security tools for analysis and protection
"""

import sys
from password_checker import display_password_report
from hash_tool import display_hash_info, calculate_string_hash
from port_scanner import scan_common_ports, scan_port_range
from file_integrity import FileIntegrityChecker


def print_banner():
    """Print the application banner."""
    banner = """
    ╔══════════════════════════════════════════════════════════╗
    ║         VAPT PROJECT - Cybersecurity Tools                ║
    ╚══════════════════════════════════════════════════════════╝
    """
    print(banner)


def password_checker_menu():
    """Password strength checker menu."""
    print("\n" + "="*50)
    print("PASSWORD STRENGTH CHECKER")
    print("="*50)
    password = input("Enter password to check: ")
    if password:
        display_password_report(password)
    else:
        print("Error: Password cannot be empty.")


def hash_tool_menu():
    """Hash generator menu."""
    print("\n" + "="*50)
    print("HASH GENERATOR & VERIFIER")
    print("="*50)
    print("1. Generate file hash")
    print("2. Generate string hash")
    
    choice = input("\nEnter choice: ").strip()
    
    if choice == '1':
        file_path = input("Enter file path: ").strip()
        algo = input("Algorithm (md5/sha1/sha256/sha512) [default: sha256]: ").lower() or 'sha256'
        display_hash_info(file_path, algo)
    elif choice == '2':
        text = input("Enter text to hash: ").strip()
        algo = input("Algorithm (md5/sha1/sha256/sha512) [default: sha256]: ").lower() or 'sha256'
        hash_value = calculate_string_hash(text, algo)
        print(f"\n{algo.upper()} Hash: {hash_value}\n")
    else:
        print("Invalid choice.")


def port_scanner_menu():
    """Port scanner menu."""
    print("\n" + "="*50)
    print("PORT SCANNER")
    print("="*50)
    host = input("Enter target host (IP or hostname): ").strip()
    
    if not host:
        print("Error: Host cannot be empty.")
        return
    
    print("\nScan type:")
    print("1. Common ports (21, 22, 23, 25, 53, 80, 110, 143, 443, etc.)")
    print("2. Custom port range")
    
    choice = input("\nEnter choice: ").strip()
    
    if choice == '1':
        scan_common_ports(host)
    elif choice == '2':
        try:
            start = int(input("Enter start port (1-65535): "))
            end = int(input("Enter end port (1-65535): "))
            scan_port_range(host, start, end)
        except ValueError:
            print("Error: Invalid port numbers.")
    else:
        print("Invalid choice.")


def file_integrity_menu():
    """File integrity checker menu."""
    checker = FileIntegrityChecker()
    
    print("\n" + "="*50)
    print("FILE INTEGRITY CHECKER")
    print("="*50)
    
    while True:
        print("\nOptions:")
        print("1. Add file to monitor")
        print("2. Check file integrity")
        print("3. Check all monitored files")
        print("4. List monitored files")
        print("5. Remove file from monitoring")
        print("6. Back to main menu")
        
        choice = input("\nEnter choice: ").strip()
        
        if choice == '1':
            file_path = input("Enter file path: ").strip()
            checker.add_file(file_path)
        elif choice == '2':
            file_path = input("Enter file path: ").strip()
            result = checker.check_file(file_path)
            print(f"\n{result['message']}")
        elif choice == '3':
            checker.check_all()
        elif choice == '4':
            checker.list_files()
        elif choice == '5':
            file_path = input("Enter file path: ").strip()
            checker.remove_file(file_path)
        elif choice == '6':
            break
        else:
            print("Invalid choice.")


def main():
    """Main application loop."""
    print_banner()
    
    while True:
        print("\n" + "="*50)
        print("MAIN MENU")
        print("="*50)
        print("1. Password Strength Checker")
        print("2. Hash Generator & Verifier")
        print("3. Port Scanner")
        print("4. File Integrity Checker")
        print("5. Exit")
        print("="*50)
        
        choice = input("\nSelect a tool (1-5): ").strip()
        
        if choice == '1':
            password_checker_menu()
        elif choice == '2':
            hash_tool_menu()
        elif choice == '3':
            port_scanner_menu()
        elif choice == '4':
            file_integrity_menu()
        elif choice == '5':
            print("\nThank you for using VAPT Project!")
            print("Stay secure! 🔒\n")
            sys.exit(0)
        else:
            print("\nInvalid choice. Please select 1-5.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user.")
        sys.exit(0)
