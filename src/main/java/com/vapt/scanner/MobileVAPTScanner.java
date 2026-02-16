package com.vapt.scanner;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * Mobile Application VAPT Scanner
 * Scans mobile applications for security vulnerabilities
 */
public class MobileVAPTScanner {
    private List<Map<String, Object>> vulnerabilities;
    private String extractedPath;
    
    public MobileVAPTScanner() {
        this.vulnerabilities = new ArrayList<>();
    }
    
    private String extractApk(String apkPath) {
        if (!Files.exists(Paths.get(apkPath))) {
            System.out.println("Error: APK file not found: " + apkPath);
            return null;
        }
        
        String extractDir = apkPath.replace(".apk", "_extracted");
        
        try {
            Files.createDirectories(Paths.get(extractDir));
            
            try (ZipInputStream zis = new ZipInputStream(new FileInputStream(apkPath))) {
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    Path filePath = Paths.get(extractDir, entry.getName());
                    if (entry.isDirectory()) {
                        Files.createDirectories(filePath);
                    } else {
                        Files.createDirectories(filePath.getParent());
                        Files.copy(zis, filePath, StandardCopyOption.REPLACE_EXISTING);
                    }
                }
            }
            
            System.out.println("[+] APK extracted to: " + extractDir);
            return extractDir;
        } catch (Exception e) {
            System.out.println("Error extracting APK: " + e.getMessage());
            return null;
        }
    }
    
    public void checkHardcodedSecrets(String extractedPath) {
        System.out.println("\n[+] Checking for hardcoded secrets...");
        
        String[] secretPatterns = {
            "password.*=.*[\"']",
            "api[_-]?key.*=.*[\"']",
            "secret.*=.*[\"']",
            "token.*=.*[\"']"
        };
        
        try {
            Files.walk(Paths.get(extractedPath))
                .filter(Files::isRegularFile)
                .filter(p -> p.toString().endsWith(".smali") || 
                            p.toString().endsWith(".java") || 
                            p.toString().endsWith(".xml"))
                .forEach(file -> {
                    try {
                        String content = new String(Files.readAllBytes(file));
                        for (String pattern : secretPatterns) {
                            Pattern p = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
                            Matcher m = p.matcher(content);
                            if (m.find() && !content.toLowerCase().contains("example") && 
                                !content.toLowerCase().contains("test")) {
                                Map<String, Object> vuln = new HashMap<>();
                                vuln.put("type", "Hardcoded Secret");
                                vuln.put("severity", "High");
                                vuln.put("file", file.toString().replace(extractedPath, ""));
                                vuln.put("evidence", "Potential secret found: " + m.group(0).substring(0, Math.min(50, m.group(0).length())) + "...");
                                vulnerabilities.add(vuln);
                                System.out.println("  [!] Potential secret in " + file + ": " + m.group(0).substring(0, Math.min(50, m.group(0).length())) + "...");
                                break;
                            }
                        }
                    } catch (IOException e) {
                        // Skip file
                    }
                });
        } catch (IOException e) {
            System.out.println("Error scanning files: " + e.getMessage());
        }
    }
    
    public List<Map<String, Object>> scanApk(String apkPath) {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("Mobile VAPT Scan: " + apkPath);
        System.out.println("=".repeat(60));
        
        System.out.println("\n[+] Starting APK scan...");
        
        extractedPath = extractApk(apkPath);
        if (extractedPath == null) {
            return vulnerabilities;
        }
        
        checkHardcodedSecrets(extractedPath);
        
        System.out.println("\n" + "=".repeat(60));
        System.out.println("Scan Complete!");
        System.out.println("Total vulnerabilities found: " + vulnerabilities.size());
        System.out.println("=".repeat(60) + "\n");
        
        return vulnerabilities;
    }
}
