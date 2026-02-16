package com.vapt.report;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * VAPT Report Generator
 * Generates comprehensive security assessment reports
 */
public class VAPTReportGenerator {
    private Map<String, Object> reportData;
    private Gson gson;
    
    public VAPTReportGenerator() {
        this.gson = new GsonBuilder().setPrettyPrinting().create();
        this.reportData = new HashMap<>();
        
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("generated_at", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
        metadata.put("tool", "VAPT Project");
        metadata.put("version", "1.0");
        
        Map<String, Integer> summary = new HashMap<>();
        summary.put("total_vulnerabilities", 0);
        summary.put("critical", 0);
        summary.put("high", 0);
        summary.put("medium", 0);
        summary.put("low", 0);
        
        Map<String, List<Map<String, Object>>> vulnerabilities = new HashMap<>();
        vulnerabilities.put("web", new ArrayList<>());
        vulnerabilities.put("api", new ArrayList<>());
        vulnerabilities.put("mobile", new ArrayList<>());
        vulnerabilities.put("aws", new ArrayList<>());
        
        reportData.put("metadata", metadata);
        reportData.put("summary", summary);
        reportData.put("vulnerabilities", vulnerabilities);
    }
    
    public void addWebVulnerabilities(List<Map<String, Object>> vulnerabilities) {
        @SuppressWarnings("unchecked")
        Map<String, List<Map<String, Object>>> vulns = (Map<String, List<Map<String, Object>>>) reportData.get("vulnerabilities");
        vulns.put("web", vulnerabilities);
        updateSummary(vulnerabilities);
    }
    
    public void addApiVulnerabilities(List<Map<String, Object>> vulnerabilities) {
        @SuppressWarnings("unchecked")
        Map<String, List<Map<String, Object>>> vulns = (Map<String, List<Map<String, Object>>>) reportData.get("vulnerabilities");
        vulns.put("api", vulnerabilities);
        updateSummary(vulnerabilities);
    }
    
    public void addMobileVulnerabilities(List<Map<String, Object>> vulnerabilities) {
        @SuppressWarnings("unchecked")
        Map<String, List<Map<String, Object>>> vulns = (Map<String, List<Map<String, Object>>>) reportData.get("vulnerabilities");
        vulns.put("mobile", vulnerabilities);
        updateSummary(vulnerabilities);
    }
    
    public void addAwsVulnerabilities(List<Map<String, Object>> vulnerabilities) {
        @SuppressWarnings("unchecked")
        Map<String, List<Map<String, Object>>> vulns = (Map<String, List<Map<String, Object>>>) reportData.get("vulnerabilities");
        vulns.put("aws", vulnerabilities);
        updateSummary(vulnerabilities);
    }
    
    @SuppressWarnings("unchecked")
    private void updateSummary(List<Map<String, Object>> vulnerabilities) {
        Map<String, Integer> summary = (Map<String, Integer>) reportData.get("summary");
        
        for (Map<String, Object> vuln : vulnerabilities) {
            String severity = ((String) vuln.getOrDefault("severity", "")).toLowerCase();
            switch (severity) {
                case "critical":
                    summary.put("critical", summary.get("critical") + 1);
                    break;
                case "high":
                    summary.put("high", summary.get("high") + 1);
                    break;
                case "medium":
                    summary.put("medium", summary.get("medium") + 1);
                    break;
                case "low":
                    summary.put("low", summary.get("low") + 1);
                    break;
            }
        }
        
        summary.put("total_vulnerabilities", 
            summary.get("critical") + summary.get("high") + 
            summary.get("medium") + summary.get("low"));
    }
    
    public void generateJsonReport(String outputPath) throws IOException {
        try (FileWriter writer = new FileWriter(outputPath)) {
            gson.toJson(reportData, writer);
            System.out.println("\n[+] JSON report saved to: " + outputPath);
        }
    }
    
    public void generateTextReport(String outputPath) throws IOException {
        try (FileWriter writer = new FileWriter(outputPath)) {
            writer.write("=".repeat(80) + "\n");
            writer.write("VAPT SECURITY ASSESSMENT REPORT\n");
            writer.write("=".repeat(80) + "\n\n");
            
            @SuppressWarnings("unchecked")
            Map<String, Object> metadata = (Map<String, Object>) reportData.get("metadata");
            writer.write("Generated: " + metadata.get("generated_at") + "\n");
            writer.write("Tool: " + metadata.get("tool") + "\n");
            writer.write("Version: " + metadata.get("version") + "\n\n");
            
            writer.write("=".repeat(80) + "\n");
            writer.write("EXECUTIVE SUMMARY\n");
            writer.write("=".repeat(80) + "\n\n");
            
            @SuppressWarnings("unchecked")
            Map<String, Integer> summary = (Map<String, Integer>) reportData.get("summary");
            writer.write("Total Vulnerabilities: " + summary.get("total_vulnerabilities") + "\n");
            writer.write("  - Critical: " + summary.get("critical") + "\n");
            writer.write("  - High: " + summary.get("high") + "\n");
            writer.write("  - Medium: " + summary.get("medium") + "\n");
            writer.write("  - Low: " + summary.get("low") + "\n\n");
            
            @SuppressWarnings("unchecked")
            Map<String, List<Map<String, Object>>> vulns = (Map<String, List<Map<String, Object>>>) reportData.get("vulnerabilities");
            
            writeVulnerabilitiesSection(writer, "WEB APPLICATION VULNERABILITIES", vulns.get("web"));
            writeVulnerabilitiesSection(writer, "API VULNERABILITIES", vulns.get("api"));
            writeVulnerabilitiesSection(writer, "MOBILE APPLICATION VULNERABILITIES", vulns.get("mobile"));
            writeVulnerabilitiesSection(writer, "AWS SECURITY VULNERABILITIES", vulns.get("aws"));
            
            writer.write("=".repeat(80) + "\n");
            writer.write("END OF REPORT\n");
            writer.write("=".repeat(80) + "\n");
        }
        System.out.println("\n[+] Text report saved to: " + outputPath);
    }
    
    private void writeVulnerabilitiesSection(FileWriter writer, String title, List<Map<String, Object>> vulnerabilities) throws IOException {
        if (vulnerabilities != null && !vulnerabilities.isEmpty()) {
            writer.write("=".repeat(80) + "\n");
            writer.write(title + "\n");
            writer.write("=".repeat(80) + "\n\n");
            
            for (int i = 0; i < vulnerabilities.size(); i++) {
                Map<String, Object> vuln = vulnerabilities.get(i);
                writer.write((i + 1) + ". " + vuln.get("type") + " (" + vuln.get("severity") + ")\n");
                writer.write("   Evidence: " + vuln.get("evidence") + "\n\n");
            }
        }
    }
    
    public void generateHtmlReport(String outputPath) throws IOException {
        try (FileWriter writer = new FileWriter(outputPath)) {
            @SuppressWarnings("unchecked")
            Map<String, Integer> summary = (Map<String, Integer>) reportData.get("summary");
            @SuppressWarnings("unchecked")
            Map<String, Object> metadata = (Map<String, Object>) reportData.get("metadata");
            
            writer.write("<!DOCTYPE html><html><head><title>VAPT Security Assessment Report</title>");
            writer.write("<style>body{font-family:Arial,sans-serif;margin:20px;background:#f5f5f5;}");
            writer.write(".container{max-width:1200px;margin:0 auto;background:white;padding:20px;box-shadow:0 0 10px rgba(0,0,0,0.1);}");
            writer.write("h1{color:#333;border-bottom:3px solid #4CAF50;padding-bottom:10px;}");
            writer.write(".summary{background:#f9f9f9;padding:15px;border-left:4px solid #2196F3;margin:20px 0;}</style></head><body>");
            writer.write("<div class='container'><h1>VAPT Security Assessment Report</h1>");
            writer.write("<div class='summary'><h2>Executive Summary</h2>");
            writer.write("<p><strong>Generated:</strong> " + metadata.get("generated_at") + "</p>");
            writer.write("<p><strong>Total Vulnerabilities:</strong> " + summary.get("total_vulnerabilities") + "</p>");
            writer.write("<ul><li>Critical: " + summary.get("critical") + "</li>");
            writer.write("<li>High: " + summary.get("high") + "</li>");
            writer.write("<li>Medium: " + summary.get("medium") + "</li>");
            writer.write("<li>Low: " + summary.get("low") + "</li></ul></div></div></body></html>");
        }
        System.out.println("\n[+] HTML report saved to: " + outputPath);
    }
}
