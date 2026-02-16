package com.vapt.scanner;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * API VAPT Scanner
 * Scans REST APIs for security vulnerabilities
 */
public class APIVAPTScanner {
    private String baseUrl;
    private int timeout;
    private List<Map<String, Object>> vulnerabilities;
    
    public APIVAPTScanner(String baseUrl) {
        this(baseUrl, 10000);
    }
    
    public APIVAPTScanner(String baseUrl, int timeout) {
        this.baseUrl = baseUrl.endsWith("/") ? 
            baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.timeout = timeout;
        this.vulnerabilities = new ArrayList<>();
    }
    
    private Response makeRequest(String url, String method, Map<String, String> headers, String data) {
        try {
            URL urlObj = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) urlObj.openConnection();
            conn.setRequestMethod(method);
            conn.setConnectTimeout(timeout);
            conn.setReadTimeout(timeout);
            
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
    
    public void checkAuthenticationBypass(String endpoint) {
        System.out.println("\n[+] Checking authentication bypass for " + endpoint + "...");
        
        String testUrl = baseUrl + endpoint;
        Response resp = makeRequest(testUrl, "GET", null, null);
        
        if (resp.code != null && resp.code == 200) {
            Map<String, Object> vuln = new HashMap<>();
            vuln.put("type", "Authentication Bypass");
            vuln.put("severity", "Critical");
            vuln.put("endpoint", endpoint);
            vuln.put("url", testUrl);
            vuln.put("evidence", "Endpoint accessible without authentication");
            vulnerabilities.add(vuln);
            System.out.println("  [!] Endpoint accessible without authentication: " + endpoint);
        }
    }
    
    public void checkRateLimiting(String endpoint) {
        System.out.println("\n[+] Checking rate limiting for " + endpoint + "...");
        
        String testUrl = baseUrl + endpoint;
        int requestsSent = 0;
        boolean rateLimitHit = false;
        
        for (int i = 0; i < 50; i++) {
            Response resp = makeRequest(testUrl, "GET", null, null);
            requestsSent++;
            
            if (resp.code != null && resp.code == 429) {
                rateLimitHit = true;
                break;
            }
            
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        
        if (!rateLimitHit && requestsSent >= 50) {
            Map<String, Object> vuln = new HashMap<>();
            vuln.put("type", "Missing Rate Limiting");
            vuln.put("severity", "Medium");
            vuln.put("endpoint", endpoint);
            vuln.put("url", testUrl);
            vuln.put("evidence", "No rate limiting detected after " + requestsSent + " requests");
            vulnerabilities.add(vuln);
            System.out.println("  [!] Missing rate limiting: " + endpoint);
        }
    }
    
    public void checkCorsMisconfiguration(String endpoint) {
        System.out.println("\n[+] Checking CORS configuration for " + endpoint + "...");
        
        String testUrl = baseUrl + endpoint;
        Map<String, String> headers = new HashMap<>();
        headers.put("Origin", "https://evil.com");
        headers.put("Access-Control-Request-Method", "POST");
        
        Response resp = makeRequest(testUrl, "OPTIONS", headers, null);
        String corsHeader = resp.headers.getOrDefault("Access-Control-Allow-Origin", "");
        
        if ("*".equals(corsHeader)) {
            Map<String, Object> vuln = new HashMap<>();
            vuln.put("type", "CORS Misconfiguration");
            vuln.put("severity", "Medium");
            vuln.put("endpoint", endpoint);
            vuln.put("url", testUrl);
            vuln.put("evidence", "CORS allows all origins (*)");
            vulnerabilities.add(vuln);
            System.out.println("  [!] CORS allows all origins: " + endpoint);
        }
    }
    
    public void scanEndpoint(String endpoint) {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("Scanning endpoint: " + endpoint);
        System.out.println("=".repeat(60));
        
        checkAuthenticationBypass(endpoint);
        checkCorsMisconfiguration(endpoint);
        checkRateLimiting(endpoint);
    }
    
    public List<Map<String, Object>> scan(List<String> endpoints) {
        if (endpoints == null || endpoints.isEmpty()) {
            endpoints = Arrays.asList("/api/users", "/api/data", "/api/v1/users", "/users", "/api");
        }
        
        System.out.println("\n" + "=".repeat(60));
        System.out.println("API VAPT Scan: " + baseUrl);
        System.out.println("=".repeat(60));
        
        System.out.println("\n[+] Starting scan...");
        
        for (String endpoint : endpoints) {
            scanEndpoint(endpoint);
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        
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
