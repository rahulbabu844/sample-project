# VAPT Project 🔒

A comprehensive Vulnerability Assessment and Penetration Testing (VAPT) toolkit for Web Applications, Mobile Applications, APIs, and AWS Cloud Infrastructure.

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

### ☁️ AWS Security VAPT Scanner
- **S3 Bucket Security**: Checks for public access, encryption, and versioning
- **IAM Policy Analysis**: Identifies overly permissive policies and missing MFA
- **EC2 Security Groups**: Detects open ports and public access misconfigurations
- **RDS Security**: Checks encryption and public accessibility
- **CloudTrail Logging**: Verifies API activity logging configuration
- **Lambda Security**: Analyzes VPC configuration and network isolation

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

2. **Prerequisites**: Java 11 or higher, Maven 3.6+

3. Build the project:
```bash
mvn clean compile
```

4. (Optional) Create an executable JAR:
```bash
mvn clean package
```

## Usage

### Running the VAPT Toolkit

Run the main VAPT interface:
```bash
mvn exec:java -Dexec.mainClass="com.vapt.VAPTMain"
```

Or if you've built the JAR:
```bash
java -jar target/vapt-project-1.0.0.jar
```

This provides an interactive menu for Web, API, Mobile, and AWS VAPT scanning.

### AWS Credentials Configuration

For AWS security scanning, configure AWS credentials using one of these methods:

1. **Environment Variables:**
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

2. **AWS Credentials File** (~/.aws/credentials):
```ini
[default]
aws_access_key_id = your_access_key
aws_secret_access_key = your_secret_key
```

3. **IAM Role** (if running on EC2 instance)

**Required AWS Permissions:**
- `s3:ListBuckets`, `s3:GetBucketPublicAccessBlock`, `s3:GetBucketEncryption`, `s3:GetBucketVersioning`
- `iam:ListPolicies`, `iam:GetPolicyVersion`, `iam:ListUsers`, `iam:ListVirtualMfaDevices`
- `ec2:DescribeSecurityGroups`
- `rds:DescribeDBInstances`
- `cloudtrail:ListTrails`, `cloudtrail:GetTrailStatus`
- `lambda:ListFunctions`
- `sts:GetCallerIdentity`

## Tool Examples

### VAPT Toolkit
```java
import com.vapt.scanner.WebVAPTScanner;
import com.vapt.scanner.APIVAPTScanner;
import com.vapt.scanner.MobileVAPTScanner;
import com.vapt.scanner.AWSSecurityScanner;
import com.vapt.report.VAPTReportGenerator;
import java.util.*;

// Web VAPT
WebVAPTScanner webScanner = new WebVAPTScanner("https://example.com");
List<Map<String, Object>> webVulns = webScanner.scan();

// API VAPT
APIVAPTScanner apiScanner = new APIVAPTScanner("https://api.example.com");
List<String> endpoints = Arrays.asList("/api/users", "/api/data");
List<Map<String, Object>> apiVulns = apiScanner.scan(endpoints);

// Mobile VAPT
MobileVAPTScanner mobileScanner = new MobileVAPTScanner();
List<Map<String, Object>> mobileVulns = mobileScanner.scanApk("app.apk");

// AWS Security VAPT
AWSSecurityScanner awsScanner = new AWSSecurityScanner("us-east-1");
List<Map<String, Object>> awsVulns = awsScanner.scan();

// Generate Report
VAPTReportGenerator reportGen = new VAPTReportGenerator();
reportGen.addWebVulnerabilities(webVulns);
reportGen.addApiVulnerabilities(apiVulns);
reportGen.addMobileVulnerabilities(mobileVulns);
reportGen.addAwsVulnerabilities(awsVulns);
reportGen.generateHtmlReport("vapt_report.html");
```

## Security Notes

⚠️ **Important Security Considerations:**

**VAPT Testing**: 
- **ONLY test applications and systems you own or have explicit written permission to test**
- Unauthorized security testing is illegal and unethical
- Always obtain proper authorization before conducting VAPT assessments
- Follow responsible disclosure practices for any vulnerabilities found
- Use rate limiting to avoid overwhelming target systems
- Respect the scope of authorized testing

**AWS Security Testing**:
- **ONLY scan AWS accounts you own or have explicit written permission to scan**
- Ensure AWS credentials have appropriate read-only permissions
- Be aware of AWS API rate limits and costs
- Review AWS CloudTrail logs to understand scan impact
- Follow AWS security best practices and compliance requirements

## Project Structure

```
VAPT-Project/
├── pom.xml                                    # Maven build configuration
├── src/main/java/com/vapt/
│   ├── VAPTMain.java                          # Main entry point
│   ├── scanner/
│   │   ├── WebVAPTScanner.java               # Web application VAPT scanner
│   │   ├── APIVAPTScanner.java                # API VAPT scanner
│   │   ├── MobileVAPTScanner.java            # Mobile application VAPT scanner
│   │   └── AWSSecurityScanner.java           # AWS security VAPT scanner
│   └── report/
│       └── VAPTReportGenerator.java           # VAPT report generator
└── README.md                                  # This file
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
