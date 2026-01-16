# Cybersecurity Toolkit 🔒

A comprehensive collection of cybersecurity tools written in Python for security analysis, password checking, file integrity monitoring, and network scanning.

## Features

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

2. No external dependencies required! This project uses only Python standard library.

3. (Optional) Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

## Usage

### Running the Main Interface

Run the main menu interface:
```bash
python main.py
```

This will present you with a menu to access all tools.

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

## Security Notes

⚠️ **Important Security Considerations:**

1. **Port Scanning**: Only scan systems you own or have explicit permission to scan. Unauthorized port scanning may be illegal.

2. **File Integrity**: The integrity database (`integrity_db.json`) should be stored securely. If compromised, an attacker could modify it to hide file changes.

3. **Password Checking**: This tool checks passwords locally. Never send passwords over unsecured networks.

4. **Hash Algorithms**: 
   - MD5 and SHA1 are considered weak and should not be used for security-critical applications
   - SHA256 and SHA512 are recommended for security purposes

## Project Structure

```
sample-project/
├── main.py                 # Main CLI interface
├── password_checker.py     # Password strength analysis
├── hash_tool.py           # Hash generation and verification
├── port_scanner.py        # Network port scanning
├── file_integrity.py      # File integrity monitoring
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
