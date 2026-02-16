"""
VAPT Report Generator
Generates comprehensive security assessment reports
"""

import json
from datetime import datetime
from pathlib import Path


class VAPTReportGenerator:
    """Generate VAPT assessment reports."""
    
    def __init__(self):
        """Initialize the report generator."""
        self.report_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool': 'VAPT Project',
                'version': '1.0'
            },
            'summary': {
                'total_vulnerabilities': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'vulnerabilities': {
                'web': [],
                'api': [],
                'mobile': []
            }
        }
    
    def add_web_vulnerabilities(self, vulnerabilities):
        """
        Add web vulnerabilities to report.
        
        Args:
            vulnerabilities (list): List of web vulnerabilities
        """
        self.report_data['vulnerabilities']['web'] = vulnerabilities
        self._update_summary(vulnerabilities)
    
    def add_api_vulnerabilities(self, vulnerabilities):
        """
        Add API vulnerabilities to report.
        
        Args:
            vulnerabilities (list): List of API vulnerabilities
        """
        self.report_data['vulnerabilities']['api'] = vulnerabilities
        self._update_summary(vulnerabilities)
    
    def add_mobile_vulnerabilities(self, vulnerabilities):
        """
        Add mobile vulnerabilities to report.
        
        Args:
            vulnerabilities (list): List of mobile vulnerabilities
        """
        self.report_data['vulnerabilities']['mobile'] = vulnerabilities
        self._update_summary(vulnerabilities)
    
    def _update_summary(self, vulnerabilities):
        """Update summary statistics."""
        for vuln in vulnerabilities:
            severity = vuln.get('severity', '').lower()
            if severity == 'critical':
                self.report_data['summary']['critical'] += 1
            elif severity == 'high':
                self.report_data['summary']['high'] += 1
            elif severity == 'medium':
                self.report_data['summary']['medium'] += 1
            elif severity == 'low':
                self.report_data['summary']['low'] += 1
        
        self.report_data['summary']['total_vulnerabilities'] = (
            self.report_data['summary']['critical'] +
            self.report_data['summary']['high'] +
            self.report_data['summary']['medium'] +
            self.report_data['summary']['low']
        )
    
    def generate_json_report(self, output_path='vapt_report.json'):
        """
        Generate JSON report.
        
        Args:
            output_path (str): Output file path
        """
        with open(output_path, 'w') as f:
            json.dump(self.report_data, f, indent=2)
        print(f"\n[+] JSON report saved to: {output_path}")
    
    def generate_text_report(self, output_path='vapt_report.txt'):
        """
        Generate text report.
        
        Args:
            output_path (str): Output file path
        """
        with open(output_path, 'w') as f:
            f.write("="*80 + "\n")
            f.write("VAPT SECURITY ASSESSMENT REPORT\n")
            f.write("="*80 + "\n\n")
            
            f.write(f"Generated: {self.report_data['metadata']['generated_at']}\n")
            f.write(f"Tool: {self.report_data['metadata']['tool']}\n")
            f.write(f"Version: {self.report_data['metadata']['version']}\n\n")
            
            f.write("="*80 + "\n")
            f.write("EXECUTIVE SUMMARY\n")
            f.write("="*80 + "\n\n")
            
            summary = self.report_data['summary']
            f.write(f"Total Vulnerabilities: {summary['total_vulnerabilities']}\n")
            f.write(f"  - Critical: {summary['critical']}\n")
            f.write(f"  - High: {summary['high']}\n")
            f.write(f"  - Medium: {summary['medium']}\n")
            f.write(f"  - Low: {summary['low']}\n\n")
            
            # Web vulnerabilities
            web_vulns = self.report_data['vulnerabilities']['web']
            if web_vulns:
                f.write("="*80 + "\n")
                f.write("WEB APPLICATION VULNERABILITIES\n")
                f.write("="*80 + "\n\n")
                
                for i, vuln in enumerate(web_vulns, 1):
                    f.write(f"{i}. {vuln['type']} ({vuln['severity']})\n")
                    f.write(f"   URL/File: {vuln.get('url', vuln.get('file', 'N/A'))}\n")
                    f.write(f"   Evidence: {vuln.get('evidence', 'N/A')}\n")
                    if 'payload' in vuln:
                        f.write(f"   Payload: {vuln['payload']}\n")
                    f.write("\n")
            
            # API vulnerabilities
            api_vulns = self.report_data['vulnerabilities']['api']
            if api_vulns:
                f.write("="*80 + "\n")
                f.write("API VULNERABILITIES\n")
                f.write("="*80 + "\n\n")
                
                for i, vuln in enumerate(api_vulns, 1):
                    f.write(f"{i}. {vuln['type']} ({vuln['severity']})\n")
                    f.write(f"   Endpoint: {vuln.get('endpoint', 'N/A')}\n")
                    f.write(f"   Evidence: {vuln.get('evidence', 'N/A')}\n")
                    if 'payload' in vuln:
                        f.write(f"   Payload: {vuln['payload']}\n")
                    f.write("\n")
            
            # Mobile vulnerabilities
            mobile_vulns = self.report_data['vulnerabilities']['mobile']
            if mobile_vulns:
                f.write("="*80 + "\n")
                f.write("MOBILE APPLICATION VULNERABILITIES\n")
                f.write("="*80 + "\n\n")
                
                for i, vuln in enumerate(mobile_vulns, 1):
                    f.write(f"{i}. {vuln['type']} ({vuln['severity']})\n")
                    f.write(f"   File: {vuln.get('file', 'N/A')}\n")
                    f.write(f"   Evidence: {vuln.get('evidence', 'N/A')}\n")
                    f.write("\n")
            
            f.write("="*80 + "\n")
            f.write("RECOMMENDATIONS\n")
            f.write("="*80 + "\n\n")
            f.write("1. Address all Critical and High severity vulnerabilities immediately\n")
            f.write("2. Implement proper input validation and sanitization\n")
            f.write("3. Use secure authentication and authorization mechanisms\n")
            f.write("4. Enable security headers and follow security best practices\n")
            f.write("5. Regularly update dependencies and frameworks\n")
            f.write("6. Conduct regular security assessments\n\n")
            
            f.write("="*80 + "\n")
            f.write("END OF REPORT\n")
            f.write("="*80 + "\n")
        
        print(f"\n[+] Text report saved to: {output_path}")
    
    def generate_html_report(self, output_path='vapt_report.html'):
        """
        Generate HTML report.
        
        Args:
            output_path (str): Output file path
        """
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>VAPT Security Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ background: #f9f9f9; padding: 15px; border-left: 4px solid #2196F3; margin: 20px 0; }}
        .vuln {{ background: #fff; border-left: 4px solid #ff9800; padding: 15px; margin: 10px 0; }}
        .critical {{ border-left-color: #f44336; }}
        .high {{ border-left-color: #ff5722; }}
        .medium {{ border-left-color: #ff9800; }}
        .low {{ border-left-color: #4CAF50; }}
        .severity {{ display: inline-block; padding: 5px 10px; border-radius: 3px; color: white; font-weight: bold; }}
        .severity.critical {{ background: #f44336; }}
        .severity.high {{ background: #ff5722; }}
        .severity.medium {{ background: #ff9800; }}
        .severity.low {{ background: #4CAF50; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #4CAF50; color: white; }}
        code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>VAPT Security Assessment Report</h1>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <p><strong>Generated:</strong> {self.report_data['metadata']['generated_at']}</p>
            <p><strong>Total Vulnerabilities:</strong> {self.report_data['summary']['total_vulnerabilities']}</p>
            <ul>
                <li>Critical: {self.report_data['summary']['critical']}</li>
                <li>High: {self.report_data['summary']['high']}</li>
                <li>Medium: {self.report_data['summary']['medium']}</li>
                <li>Low: {self.report_data['summary']['low']}</li>
            </ul>
        </div>
"""
        
        # Web vulnerabilities
        web_vulns = self.report_data['vulnerabilities']['web']
        if web_vulns:
            html += '<h2>Web Application Vulnerabilities</h2>'
            for vuln in web_vulns:
                severity_class = vuln.get('severity', 'medium').lower()
                html += f"""
                <div class="vuln {severity_class}">
                    <h3>{vuln['type']} <span class="severity {severity_class}">{vuln['severity']}</span></h3>
                    <p><strong>URL/File:</strong> <code>{vuln.get('url', vuln.get('file', 'N/A'))}</code></p>
                    <p><strong>Evidence:</strong> {vuln.get('evidence', 'N/A')}</p>
                    {f"<p><strong>Payload:</strong> <code>{vuln['payload']}</code></p>" if 'payload' in vuln else ''}
                </div>
"""
        
        # API vulnerabilities
        api_vulns = self.report_data['vulnerabilities']['api']
        if api_vulns:
            html += '<h2>API Vulnerabilities</h2>'
            for vuln in api_vulns:
                severity_class = vuln.get('severity', 'medium').lower()
                html += f"""
                <div class="vuln {severity_class}">
                    <h3>{vuln['type']} <span class="severity {severity_class}">{vuln['severity']}</span></h3>
                    <p><strong>Endpoint:</strong> <code>{vuln.get('endpoint', 'N/A')}</code></p>
                    <p><strong>Evidence:</strong> {vuln.get('evidence', 'N/A')}</p>
                    {f"<p><strong>Payload:</strong> <code>{vuln['payload']}</code></p>" if 'payload' in vuln else ''}
                </div>
"""
        
        # Mobile vulnerabilities
        mobile_vulns = self.report_data['vulnerabilities']['mobile']
        if mobile_vulns:
            html += '<h2>Mobile Application Vulnerabilities</h2>'
            for vuln in mobile_vulns:
                severity_class = vuln.get('severity', 'medium').lower()
                html += f"""
                <div class="vuln {severity_class}">
                    <h3>{vuln['type']} <span class="severity {severity_class}">{vuln['severity']}</span></h3>
                    <p><strong>File:</strong> <code>{vuln.get('file', 'N/A')}</code></p>
                    <p><strong>Evidence:</strong> {vuln.get('evidence', 'N/A')}</p>
                </div>
"""
        
        html += """
        <h2>Recommendations</h2>
        <ul>
            <li>Address all Critical and High severity vulnerabilities immediately</li>
            <li>Implement proper input validation and sanitization</li>
            <li>Use secure authentication and authorization mechanisms</li>
            <li>Enable security headers and follow security best practices</li>
            <li>Regularly update dependencies and frameworks</li>
            <li>Conduct regular security assessments</li>
        </ul>
    </div>
</body>
</html>
"""
        
        with open(output_path, 'w') as f:
            f.write(html)
        
        print(f"\n[+] HTML report saved to: {output_path}")


if __name__ == "__main__":
    generator = VAPTReportGenerator()
    
    # Example usage
    generator.add_web_vulnerabilities([
        {
            'type': 'SQL Injection',
            'severity': 'High',
            'url': 'https://example.com/login',
            'evidence': 'SQL error detected',
            'payload': "' OR '1'='1"
        }
    ])
    
    generator.generate_json_report()
    generator.generate_text_report()
    generator.generate_html_report()
