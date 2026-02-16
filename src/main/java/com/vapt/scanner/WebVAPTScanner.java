package com.vapt.scanner;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * Web Application VAPT Scanner
 * Scans web applications for common vulnerabilities
 */
public class WebVAPTScanner {
    private String targetUrl;
    private int timeout;
    private List<Map<String, Object>> vulnerabilities;
    
    public WebVAPTScanner(String targetUrl) {
        this(targetUrl, 10000);
    }
    
    public WebVAPTScanner(String targetUrl, int timeout) {
        this.targetUrl = targetUrl.endsWith("/") ? 
            targetUrl.substring(0, targetUrl.length() - 1) : targetUrl;
        this.timeout = timeout;
        this.vulnerabilities = new ArrayList<>();
    }
    
    private Response makeRequest(String url, String method, String data, Map<String, String> headers) {
        try {
            URL urlObj = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) urlObj.openConnection();
            conn.setRequestMethod(method);
            conn.setConnectTimeout(timeout);
            conn.setReadTimeout(timeout);
            conn.setInstanceFollowRedirects(false);
            
            if (headers != null) {
                for (Map.Entry<String, String> entry : headers.entrySet()) {
                    conn.setRequestProperty(entry.getKey(), entry.getValue());
                }
            }
            
            if (data != null && (method.equals("POST") || method.equals("PUT"))) {
                conn.setDoOutput(true);
                conn.getOutputStream().write(data.getBytes());
            }
            
            int responseCode = conn.getResponseCode();
            StringBuilder response = new StringBuilder();
            
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line).append("\n");
                }
            }
            
            Map<String, String> responseHeaders = new HashMap<>();
            conn.getHeaderFields().forEach((key, values) -> {
                if (key != null && !values.isEmpty()) {
                    responseHeaders.put(key, values.get(0));
                }
            });
            
            return new Response(responseCode, response.toString(), responseHeaders);
        } catch (Exception e) {
            return new Response(null, e.getMessage(), new HashMap<>());
        }
    }
    
    public void checkSqlInjection(Map<String, String> params) {
        System.out.println("\n[+] Checking for SQL Injection vulnerabilities...");
        
        String[] sqlPayloads = {
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "1' UNION SELECT NULL--",
            "' OR 1=1--"
        };
        
        if (params == null) {
            params = new HashMap<>();
            params.put("id", "1");
            params.put("user", "admin");
        }
        
        for (Map.Entry<String, String> param : params.entrySet()) {
            for (String payload : sqlPayloads) {
                String testValue = param.getValue() + payload;
                String testUrl = targetUrl + "?" + param.getKey() + "=" + 
                    java.net.URLEncoder.encode(testValue, java.nio.charset.StandardCharsets.UTF_8);
                
                Response resp = makeRequest(testUrl, "GET", null, null);
                
                if (resp.body != null && !resp.body.isEmpty()) {
                    String[] errorPatterns = {
                        "mysql_fetch",
                        "PostgreSQL.*ERROR",
                        "Warning.*\\Wmysql_",
                        "valid MySQL result",
                        "MySqlClient\\.",
                        "SQL syntax.*MySQL",
                        "Warning.*\\Wpg_",
                        "PostgreSQL query failed",
                        "Warning.*\\Woci_",
                        "Warning.*\\Wodbc_",
                        "Microsoft Access.*Driver",
                        "ODBC SQL Server Driver",
                        "SQLServer JDBC Driver",
                        "SQLException",
                        "SQLite.*error"
                    };
                    
                    for (String pattern : errorPatterns) {
                        Pattern p = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
                        Matcher m = p.matcher(resp.body);
                        if (m.find()) {
                            Map<String, Object> vuln = new HashMap<>();
                            vuln.put("type", "SQL Injection");
                            vuln.put("severity", "High");
                            vuln.put("parameter", param.getKey());
                            vuln.put("payload", payload);
                            vuln.put("url", testUrl);
                            vuln.put("evidence", "Database error pattern detected: " + pattern);
                            vulnerabilities.add(vuln);
                            System.out.println("  [!] Potential SQL Injection found in parameter: " + param.getKey());
                            System.out.println("      Payload: " + payload);
                            break;
                        }
                    }
                }
                
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }
    
    public void checkXss(Map<String, String> params) {
        System.out.println("\n[+] Checking for XSS vulnerabilities...");
        
        String[] xssPayloads = {
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>"
        };
        
        if (params == null) {
            params = new HashMap<>();
            params.put("q", "test");
            params.put("search", "test");
            params.put("name", "test");
        }
        
        for (Map.Entry<String, String> param : params.entrySet()) {
            for (String payload : xssPayloads) {
                String testUrl = targetUrl + "?" + param.getKey() + "=" + 
                    java.net.URLEncoder.encode(payload, java.nio.charset.StandardCharsets.UTF_8);
                
                Response resp = makeRequest(testUrl, "GET", null, null);
                
                if (resp.body != null && resp.body.contains(payload)) {
                    Map<String, Object> vuln = new HashMap<>();
                    vuln.put("type", "Cross-Site Scripting (XSS)");
                    vuln.put("severity", "Medium");
                    vuln.put("parameter", param.getKey());
                    vuln.put("payload", payload);
                    vuln.put("url", testUrl);
                    vuln.put("evidence", "Payload reflected in response without proper encoding");
                    vulnerabilities.add(vuln);
                    System.out.println("  [!] Potential XSS found in parameter: " + param.getKey());
                    System.out.println("      Payload: " + (payload.length() > 50 ? payload.substring(0, 50) + "..." : payload));
                    break;
                }
                
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }
    
    public void checkDirectoryTraversal() {
        System.out.println("\n[+] Checking for Directory Traversal vulnerabilities...");
        
        String[] traversalPayloads = {
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        };
        
        String[] testParams = {"file", "path", "page", "include", "doc"};
        
        for (String param : testParams) {
            for (String payload : traversalPayloads) {
                String testUrl = targetUrl + "?" + param + "=" + 
                    java.net.URLEncoder.encode(payload, java.nio.charset.StandardCharsets.UTF_8);
                
                Response resp = makeRequest(testUrl, "GET", null, null);
                
                if (resp.body != null && (resp.body.contains("root:") || resp.body.toLowerCase().contains("[boot loader]"))) {
                    Map<String, Object> vuln = new HashMap<>();
                    vuln.put("type", "Directory Traversal");
                    vuln.put("severity", "High");
                    vuln.put("parameter", param);
                    vuln.put("payload", payload);
                    vuln.put("url", testUrl);
                    vuln.put("evidence", "System file content detected in response");
                    vulnerabilities.add(vuln);
                    System.out.println("  [!] Potential Directory Traversal found in parameter: " + param);
                    break;
                }
                
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }
    
    public void checkSensitiveFiles() {
        System.out.println("\n[+] Checking for exposed sensitive files...");
        
        String[] sensitiveFiles = {
            "/.env", "/config.php", "/.git/config", "/.svn/entries",
            "/web.config", "/phpinfo.php", "/.htaccess", "/robots.txt",
            "/sitemap.xml", "/backup.sql", "/database.sql"
        };
        
        String[] sensitivePatterns = {
            "DB_PASSWORD", "API_KEY", "SECRET", "password.*=", "\\[core\\]"
        };
        
        for (String filePath : sensitiveFiles) {
            String testUrl = targetUrl + filePath;
            Response resp = makeRequest(testUrl, "GET", null, null);
            
            if (resp.code != null && resp.code == 200 && resp.body != null) {
                for (String pattern : sensitivePatterns) {
                    Pattern p = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
                    Matcher m = p.matcher(resp.body);
                    if (m.find()) {
                        Map<String, Object> vuln = new HashMap<>();
                        vuln.put("type", "Exposed Sensitive File");
                        vuln.put("severity", "High");
                        vuln.put("file", filePath);
                        vuln.put("url", testUrl);
                        vuln.put("evidence", "Sensitive pattern detected: " + pattern);
                        vulnerabilities.add(vuln);
                        System.out.println("  [!] Sensitive file exposed: " + filePath);
                        break;
                    }
                }
            }
            
            try {
                Thread.sleep(300);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
    
    public void checkHttpMethods() {
        System.out.println("\n[+] Checking HTTP methods...");
        
        String[] methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "HEAD"};
        List<String> allowedMethods = new ArrayList<>();
        
        for (String method : methods) {
            Response resp = makeRequest(targetUrl, method, null, null);
            if (resp.code != null && resp.code != 405) {
                allowedMethods.add(method);
            }
        }
        
        String[] dangerousMethods = {"PUT", "DELETE", "TRACE"};
        for (String method : dangerousMethods) {
            if (allowedMethods.contains(method)) {
                Map<String, Object> vuln = new HashMap<>();
                vuln.put("type", "Insecure HTTP Method");
                vuln.put("severity", "Medium");
                vuln.put("method", method);
                vuln.put("url", targetUrl);
                vuln.put("evidence", "Dangerous HTTP method " + method + " is enabled");
                vulnerabilities.add(vuln);
                System.out.println("  [!] Dangerous HTTP method enabled: " + method);
            }
        }
    }
    
    public void checkSecurityHeaders() {
        System.out.println("\n[+] Checking security headers...");
        
        Response resp = makeRequest(targetUrl, "GET", null, null);
        
        Map<String, String> securityHeaders = new HashMap<>();
        securityHeaders.put("X-Content-Type-Options", "nosniff");
        securityHeaders.put("X-Frame-Options", "DENY");
        securityHeaders.put("X-XSS-Protection", "1");
        securityHeaders.put("Strict-Transport-Security", null);
        securityHeaders.put("Content-Security-Policy", null);
        
        for (Map.Entry<String, String> header : securityHeaders.entrySet()) {
            String headerValue = resp.headers.getOrDefault(header.getKey(), "");
            
            if (headerValue.isEmpty()) {
                Map<String, Object> vuln = new HashMap<>();
                vuln.put("type", "Missing Security Header");
                vuln.put("severity", "Low");
                vuln.put("header", header.getKey());
                vuln.put("url", targetUrl);
                vuln.put("evidence", "Security header " + header.getKey() + " is missing");
                vulnerabilities.add(vuln);
                System.out.println("  [!] Missing security header: " + header.getKey());
            }
        }
    }
    
    public List<Map<String, Object>> scan() {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("Web VAPT Scan: " + targetUrl);
        System.out.println("=".repeat(60));
        
        System.out.println("\n[+] Starting scan...");
        
        checkSecurityHeaders();
        checkHttpMethods();
        checkSensitiveFiles();
        checkSqlInjection(null);
        checkXss(null);
        checkDirectoryTraversal();
        
        System.out.println("\n" + "=".repeat(60));
        System.out.println("Scan Complete!");
        System.out.println("Total vulnerabilities found: " + vulnerabilities.size());
        System.out.println("=".repeat(60) + "\n");
        
        return vulnerabilities;
    }
    
    private static class Response {
        Integer code;
        String body;
        Map<String, String> headers;
        
        Response(Integer code, String body, Map<String, String> headers) {
            this.code = code;
            this.body = body;
            this.headers = headers;
        }
    }
}
