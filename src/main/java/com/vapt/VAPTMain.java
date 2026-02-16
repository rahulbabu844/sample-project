package com.vapt;

import com.vapt.scanner.WebVAPTScanner;
import com.vapt.scanner.APIVAPTScanner;
import com.vapt.scanner.MobileVAPTScanner;
import com.vapt.scanner.AWSSecurityScanner;
import com.vapt.report.VAPTReportGenerator;

import java.util.*;

/**
 * VAPT Project - Main Interface
 * Vulnerability Assessment and Penetration Testing for Web, Mobile, API, and AWS
 */
public class VAPTMain {
    
    private static List<Map<String, Object>> webVulnerabilities = new ArrayList<>();
    private static List<Map<String, Object>> apiVulnerabilities = new ArrayList<>();
    private static List<Map<String, Object>> mobileVulnerabilities = new ArrayList<>();
    private static List<Map<String, Object>> awsVulnerabilities = new ArrayList<>();
    
    public static void main(String[] args) {
        printBanner();
        
        Scanner scanner = new Scanner(System.in);
        
        while (true) {
            printMainMenu();
            System.out.print("\nSelect an option (1-7): ");
            String choice = scanner.nextLine().trim();
            
            switch (choice) {
                case "1":
                    webVAPTMenu(scanner);
                    break;
                case "2":
                    apiVAPTMenu(scanner);
                    break;
                case "3":
                    mobileVAPTMenu(scanner);
                    break;
                case "4":
                    awsVAPTMenu(scanner);
                    break;
                case "5":
                    generateReportMenu(scanner);
                    break;
                case "6":
                    viewCurrentResults();
                    break;
                case "7":
                    System.out.println("\nThank you for using VAPT Project!");
                    System.out.println("Stay secure! 🔒\n");
                    scanner.close();
                    System.exit(0);
                    break;
                default:
                    System.out.println("\nInvalid choice. Please select 1-7.");
            }
        }
    }
    
    private static void printBanner() {
        String banner = """
            ╔══════════════════════════════════════════════════════════════╗
            ║         VAPT PROJECT - Vulnerability Assessment              ║
            ║         Web | Mobile | API | AWS Security Testing            ║
            ╚══════════════════════════════════════════════════════════════╝
            """;
        System.out.println(banner);
    }
    
    private static void printMainMenu() {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("MAIN MENU");
        System.out.println("=".repeat(60));
        System.out.println("1. Web Application VAPT");
        System.out.println("2. API VAPT");
        System.out.println("3. Mobile Application VAPT");
        System.out.println("4. AWS Security VAPT");
        System.out.println("5. Generate Report");
        System.out.println("6. View Current Results");
        System.out.println("7. Exit");
        System.out.println("=".repeat(60));
    }
    
    private static void webVAPTMenu(Scanner scanner) {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("WEB APPLICATION VAPT");
        System.out.println("=".repeat(60));
        
        System.out.print("Enter target URL: ");
        String targetUrl = scanner.nextLine().trim();
        
        if (targetUrl.isEmpty()) {
            System.out.println("Error: URL cannot be empty.");
            return;
        }
        
        if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
            targetUrl = "https://" + targetUrl;
        }
        
        try {
            WebVAPTScanner webScanner = new WebVAPTScanner(targetUrl);
            List<Map<String, Object>> vulns = webScanner.scan();
            webVulnerabilities = vulns;
            System.out.println("\n[+] Found " + vulns.size() + " web vulnerabilities");
        } catch (Exception e) {
            System.out.println("Error during scan: " + e.getMessage());
        }
    }
    
    private static void apiVAPTMenu(Scanner scanner) {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("API VAPT");
        System.out.println("=".repeat(60));
        
        System.out.print("Enter API base URL: ");
        String baseUrl = scanner.nextLine().trim();
        
        if (baseUrl.isEmpty()) {
            System.out.println("Error: Base URL cannot be empty.");
            return;
        }
        
        if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) {
            baseUrl = "https://" + baseUrl;
        }
        
        System.out.print("Enter endpoints (comma-separated, or press Enter for default): ");
        String endpointsInput = scanner.nextLine().trim();
        
        List<String> endpoints = null;
        if (!endpointsInput.isEmpty()) {
            endpoints = Arrays.asList(endpointsInput.split(","));
            endpoints.replaceAll(String::trim);
        }
        
        try {
            APIVAPTScanner apiScanner = new APIVAPTScanner(baseUrl);
            List<Map<String, Object>> vulns = apiScanner.scan(endpoints);
            apiVulnerabilities = vulns;
            System.out.println("\n[+] Found " + vulns.size() + " API vulnerabilities");
        } catch (Exception e) {
            System.out.println("Error during scan: " + e.getMessage());
        }
    }
    
    private static void mobileVAPTMenu(Scanner scanner) {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("MOBILE APPLICATION VAPT");
        System.out.println("=".repeat(60));
        
        System.out.print("Enter APK file path: ");
        String apkPath = scanner.nextLine().trim();
        
        if (apkPath.isEmpty()) {
            System.out.println("Error: APK path cannot be empty.");
            return;
        }
        
        try {
            MobileVAPTScanner mobileScanner = new MobileVAPTScanner();
            List<Map<String, Object>> vulns = mobileScanner.scanApk(apkPath);
            mobileVulnerabilities = vulns;
            System.out.println("\n[+] Found " + vulns.size() + " mobile vulnerabilities");
        } catch (Exception e) {
            System.out.println("Error during scan: " + e.getMessage());
        }
    }
    
    private static void awsVAPTMenu(Scanner scanner) {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("AWS SECURITY VAPT");
        System.out.println("=".repeat(60));
        
        System.out.print("Enter AWS region (or press Enter for us-east-1): ");
        String region = scanner.nextLine().trim();
        if (region.isEmpty()) {
            region = "us-east-1";
        }
        
        System.out.println("\n[!] Make sure AWS credentials are configured:");
        System.out.println("    - AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables");
        System.out.println("    - Or ~/.aws/credentials file");
        System.out.println("    - Or IAM role (if running on EC2)");
        
        try {
            AWSSecurityScanner awsScanner = new AWSSecurityScanner(region);
            List<Map<String, Object>> vulns = awsScanner.scan();
            awsVulnerabilities = vulns;
            System.out.println("\n[+] Found " + vulns.size() + " AWS security vulnerabilities");
        } catch (Exception e) {
            System.out.println("Error during scan: " + e.getMessage());
            System.out.println("Make sure AWS credentials are properly configured.");
        }
    }
    
    private static void generateReportMenu(Scanner scanner) {
        if (webVulnerabilities.isEmpty() && apiVulnerabilities.isEmpty() && 
            mobileVulnerabilities.isEmpty() && awsVulnerabilities.isEmpty()) {
            System.out.println("\n[!] No vulnerabilities found yet. Please run scans first.");
            return;
        }
        
        System.out.println("\n" + "=".repeat(60));
        System.out.println("GENERATE VAPT REPORT");
        System.out.println("=".repeat(60));
        
        VAPTReportGenerator generator = new VAPTReportGenerator();
        
        if (!webVulnerabilities.isEmpty()) {
            generator.addWebVulnerabilities(webVulnerabilities);
        }
        if (!apiVulnerabilities.isEmpty()) {
            generator.addApiVulnerabilities(apiVulnerabilities);
        }
        if (!mobileVulnerabilities.isEmpty()) {
            generator.addMobileVulnerabilities(mobileVulnerabilities);
        }
        if (!awsVulnerabilities.isEmpty()) {
            generator.addAwsVulnerabilities(awsVulnerabilities);
        }
        
        System.out.println("\nSelect report format:");
        System.out.println("1. JSON");
        System.out.println("2. Text");
        System.out.println("3. HTML");
        System.out.println("4. All formats");
        
        System.out.print("\nEnter choice: ");
        String choice = scanner.nextLine().trim();
        
        try {
            switch (choice) {
                case "1":
                    generator.generateJsonReport("vapt_report.json");
                    break;
                case "2":
                    generator.generateTextReport("vapt_report.txt");
                    break;
                case "3":
                    generator.generateHtmlReport("vapt_report.html");
                    break;
                case "4":
                    generator.generateJsonReport("vapt_report.json");
                    generator.generateTextReport("vapt_report.txt");
                    generator.generateHtmlReport("vapt_report.html");
                    break;
                default:
                    System.out.println("Invalid choice.");
            }
        } catch (Exception e) {
            System.out.println("Error generating report: " + e.getMessage());
        }
    }
    
    private static void viewCurrentResults() {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("CURRENT RESULTS");
        System.out.println("=".repeat(60));
        System.out.println("Web Vulnerabilities: " + webVulnerabilities.size());
        System.out.println("API Vulnerabilities: " + apiVulnerabilities.size());
        System.out.println("Mobile Vulnerabilities: " + mobileVulnerabilities.size());
        System.out.println("AWS Vulnerabilities: " + awsVulnerabilities.size());
        System.out.println("Total: " + (webVulnerabilities.size() + apiVulnerabilities.size() + 
            mobileVulnerabilities.size() + awsVulnerabilities.size()));
    }
}
