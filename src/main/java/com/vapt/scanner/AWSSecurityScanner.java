package com.vapt.scanner;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.*;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.*;
import software.amazon.awssdk.services.rds.RdsClient;
import software.amazon.awssdk.services.rds.model.*;
import software.amazon.awssdk.services.cloudtrail.CloudTrailClient;
import software.amazon.awssdk.services.cloudtrail.model.*;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.*;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;

import java.util.*;

/**
 * AWS Security Scanner
 * Scans AWS infrastructure for security vulnerabilities and misconfigurations
 */
public class AWSSecurityScanner {
    private String region;
    private List<Map<String, Object>> vulnerabilities;
    private Region awsRegion;
    
    public AWSSecurityScanner(String region) {
        this.region = region != null ? region : "us-east-1";
        this.awsRegion = Region.of(this.region);
        this.vulnerabilities = new ArrayList<>();
    }
    
    public AWSSecurityScanner() {
        this("us-east-1");
    }
    
    /**
     * Check current AWS account identity
     */
    public void checkAccountIdentity() {
        System.out.println("\n[+] Checking AWS Account Identity...");
        
        try (StsClient stsClient = StsClient.builder()
                .region(awsRegion)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build()) {
            
            GetCallerIdentityRequest request = GetCallerIdentityRequest.builder().build();
            var response = stsClient.getCallerIdentity(request);
            
            System.out.println("  [+] Account ID: " + response.account());
            System.out.println("  [+] User ARN: " + response.arn());
            System.out.println("  [+] Region: " + region);
        } catch (Exception e) {
            System.out.println("  [!] Error checking account identity: " + e.getMessage());
            System.out.println("  [!] Make sure AWS credentials are configured properly");
        }
    }
    
    /**
     * Scan S3 buckets for security issues
     */
    public void scanS3Buckets() {
        System.out.println("\n[+] Scanning S3 buckets for security issues...");
        
        try (S3Client s3Client = S3Client.builder()
                .region(awsRegion)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build()) {
            
            ListBucketsResponse bucketsResponse = s3Client.listBuckets();
            
            for (Bucket bucket : bucketsResponse.buckets()) {
                String bucketName = bucket.name();
                System.out.println("  [+] Checking bucket: " + bucketName);
                
                try {
                    // Check public access block
                    GetPublicAccessBlockRequest publicAccessRequest = GetPublicAccessBlockRequest.builder()
                            .bucket(bucketName)
                            .build();
                    
                    try {
                        GetPublicAccessBlockResponse publicAccessResponse = s3Client.getPublicAccessBlock(publicAccessRequest);
                        PublicAccessBlockConfiguration config = publicAccessResponse.publicAccessBlockConfiguration();
                        
                        if (!config.blockPublicAcls() || !config.blockPublicPolicy() || 
                            !config.ignorePublicAcls() || !config.restrictPublicBuckets()) {
                            Map<String, Object> vuln = new HashMap<>();
                            vuln.put("type", "S3 Public Access Not Fully Blocked");
                            vuln.put("severity", "High");
                            vuln.put("resource", "s3://" + bucketName);
                            vuln.put("evidence", "Public access block is not fully configured");
                            vulnerabilities.add(vuln);
                            System.out.println("    [!] Public access block not fully configured");
                        }
                    } catch (NoSuchPublicAccessBlockConfigurationException e) {
                        Map<String, Object> vuln = new HashMap<>();
                        vuln.put("type", "S3 Public Access Block Not Configured");
                        vuln.put("severity", "Critical");
                        vuln.put("resource", "s3://" + bucketName);
                        vuln.put("evidence", "Public access block is not configured - bucket may be publicly accessible");
                        vulnerabilities.add(vuln);
                        System.out.println("    [!] Public access block not configured");
                    }
                    
                    // Check bucket encryption
                    GetBucketEncryptionRequest encryptionRequest = GetBucketEncryptionRequest.builder()
                            .bucket(bucketName)
                            .build();
                    
                    try {
                        GetBucketEncryptionResponse encryptionResponse = s3Client.getBucketEncryption(encryptionRequest);
                        // Encryption is configured
                        System.out.println("    [+] Encryption configured");
                    } catch (ServerSideEncryptionConfigurationNotFoundException e) {
                        Map<String, Object> vuln = new HashMap<>();
                        vuln.put("type", "S3 Bucket Encryption Not Enabled");
                        vuln.put("severity", "Medium");
                        vuln.put("resource", "s3://" + bucketName);
                        vuln.put("evidence", "Server-side encryption is not enabled");
                        vulnerabilities.add(vuln);
                        System.out.println("    [!] Encryption not enabled");
                    }
                    
                    // Check bucket versioning
                    GetBucketVersioningRequest versioningRequest = GetBucketVersioningRequest.builder()
                            .bucket(bucketName)
                            .build();
                    
                    GetBucketVersioningResponse versioningResponse = s3Client.getBucketVersioning(versioningRequest);
                    if (versioningResponse.status() != BucketVersioningStatus.ENABLED) {
                        Map<String, Object> vuln = new HashMap<>();
                        vuln.put("type", "S3 Bucket Versioning Not Enabled");
                        vuln.put("severity", "Low");
                        vuln.put("resource", "s3://" + bucketName);
                        vuln.put("evidence", "Versioning is not enabled - data recovery may be difficult");
                        vulnerabilities.add(vuln);
                        System.out.println("    [!] Versioning not enabled");
                    }
                    
                } catch (Exception e) {
                    System.out.println("    [-] Error checking bucket " + bucketName + ": " + e.getMessage());
                }
            }
            
        } catch (Exception e) {
            System.out.println("  [!] Error scanning S3 buckets: " + e.getMessage());
            System.out.println("  [!] Make sure you have s3:ListBuckets permission");
        }
    }
    
    /**
     * Scan IAM policies for security issues
     */
    public void scanIAMPolicies() {
        System.out.println("\n[+] Scanning IAM policies for security issues...");
        
        try (IamClient iamClient = IamClient.builder()
                .region(Region.AWS_GLOBAL)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build()) {
            
            // Check for overly permissive policies
            ListPoliciesRequest policiesRequest = ListPoliciesRequest.builder()
                    .scope(PolicyScopeType.LOCAL)
                    .maxItems(100)
                    .build();
            
            ListPoliciesResponse policiesResponse = iamClient.listPolicies(policiesRequest);
            
            for (Policy policy : policiesResponse.policies()) {
                String policyArn = policy.arn();
                
                // Check for wildcard actions
                GetPolicyVersionRequest versionRequest = GetPolicyVersionRequest.builder()
                        .policyArn(policyArn)
                        .versionId(policy.defaultVersionId())
                        .build();
                
                try {
                    GetPolicyVersionResponse versionResponse = iamClient.getPolicyVersion(versionRequest);
                    String policyDocument = versionResponse.policyVersion().document();
                    
                    if (policyDocument.contains("\"Action\": \"*\"") || 
                        policyDocument.contains("\"Effect\": \"Allow\"") && policyDocument.contains("\"Resource\": \"*\"")) {
                        Map<String, Object> vuln = new HashMap<>();
                        vuln.put("type", "Overly Permissive IAM Policy");
                        vuln.put("severity", "High");
                        vuln.put("resource", policyArn);
                        vuln.put("evidence", "Policy contains wildcard actions or resources");
                        vulnerabilities.add(vuln);
                        System.out.println("    [!] Overly permissive policy: " + policy.policyName());
                    }
                } catch (Exception e) {
                    // Skip if can't read policy
                }
            }
            
            // Check for users without MFA
            ListUsersRequest usersRequest = ListUsersRequest.builder().build();
            ListUsersResponse usersResponse = iamClient.listUsers(usersRequest);
            
            for (User user : usersResponse.users()) {
                ListVirtualMfaDevicesRequest mfaRequest = ListVirtualMfaDevicesRequest.builder().build();
                ListVirtualMfaDevicesResponse mfaResponse = iamClient.listVirtualMfaDevices(mfaRequest);
                
                boolean hasMfa = mfaResponse.virtualMfaDevices().stream()
                        .anyMatch(device -> device.user().userName().equals(user.userName()));
                
                if (!hasMfa) {
                    Map<String, Object> vuln = new HashMap<>();
                    vuln.put("type", "IAM User Without MFA");
                    vuln.put("severity", "Medium");
                    vuln.put("resource", "user:" + user.userName());
                    vuln.put("evidence", "User does not have MFA enabled");
                    vulnerabilities.add(vuln);
                    System.out.println("    [!] User without MFA: " + user.userName());
                }
            }
            
        } catch (Exception e) {
            System.out.println("  [!] Error scanning IAM policies: " + e.getMessage());
            System.out.println("  [!] Make sure you have iam:ListPolicies permission");
        }
    }
    
    /**
     * Scan EC2 security groups for misconfigurations
     */
    public void scanEC2SecurityGroups() {
        System.out.println("\n[+] Scanning EC2 security groups...");
        
        try (Ec2Client ec2Client = Ec2Client.builder()
                .region(awsRegion)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build()) {
            
            DescribeSecurityGroupsRequest sgRequest = DescribeSecurityGroupsRequest.builder().build();
            DescribeSecurityGroupsResponse sgResponse = ec2Client.describeSecurityGroups(sgRequest);
            
            for (SecurityGroup sg : sgResponse.securityGroups()) {
                for (IpPermission permission : sg.ipPermissions()) {
                    // Check for open ports to the world
                    for (IpRange ipRange : permission.ipRanges()) {
                        if ("0.0.0.0/0".equals(ipRange.cidrIp()) || "::/0".equals(ipRange.ipv6CidrBlock())) {
                            Map<String, Object> vuln = new HashMap<>();
                            vuln.put("type", "Security Group Allows Public Access");
                            vuln.put("severity", "High");
                            vuln.put("resource", "sg:" + sg.groupId());
                            vuln.put("evidence", "Security group " + sg.groupId() + " allows access from 0.0.0.0/0 on port " + 
                                    (permission.fromPort() != null ? permission.fromPort() : "all"));
                            vulnerabilities.add(vuln);
                            System.out.println("    [!] Security group " + sg.groupId() + " allows public access");
                        }
                    }
                }
            }
            
        } catch (Exception e) {
            System.out.println("  [!] Error scanning EC2 security groups: " + e.getMessage());
            System.out.println("  [!] Make sure you have ec2:DescribeSecurityGroups permission");
        }
    }
    
    /**
     * Scan RDS instances for security issues
     */
    public void scanRDSInstances() {
        System.out.println("\n[+] Scanning RDS instances...");
        
        try (RdsClient rdsClient = RdsClient.builder()
                .region(awsRegion)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build()) {
            
            DescribeDbInstancesRequest rdsRequest = DescribeDbInstancesRequest.builder().build();
            DescribeDbInstancesResponse rdsResponse = rdsClient.describeDBInstances(rdsRequest);
            
            for (DBInstance instance : rdsResponse.dbInstances()) {
                // Check if encryption is enabled
                if (!instance.storageEncrypted()) {
                    Map<String, Object> vuln = new HashMap<>();
                    vuln.put("type", "RDS Instance Encryption Not Enabled");
                    vuln.put("severity", "High");
                    vuln.put("resource", "rds:" + instance.dbInstanceIdentifier());
                    vuln.put("evidence", "RDS instance encryption is not enabled");
                    vulnerabilities.add(vuln);
                    System.out.println("    [!] RDS instance " + instance.dbInstanceIdentifier() + " not encrypted");
                }
                
                // Check if publicly accessible
                if (instance.publiclyAccessible()) {
                    Map<String, Object> vuln = new HashMap<>();
                    vuln.put("type", "RDS Instance Publicly Accessible");
                    vuln.put("severity", "Critical");
                    vuln.put("resource", "rds:" + instance.dbInstanceIdentifier());
                    vuln.put("evidence", "RDS instance is publicly accessible");
                    vulnerabilities.add(vuln);
                    System.out.println("    [!] RDS instance " + instance.dbInstanceIdentifier() + " is publicly accessible");
                }
            }
            
        } catch (Exception e) {
            System.out.println("  [!] Error scanning RDS instances: " + e.getMessage());
            System.out.println("  [!] Make sure you have rds:DescribeDBInstances permission");
        }
    }
    
    /**
     * Check CloudTrail logging configuration
     */
    public void checkCloudTrail() {
        System.out.println("\n[+] Checking CloudTrail configuration...");
        
        try (CloudTrailClient cloudTrailClient = CloudTrailClient.builder()
                .region(awsRegion)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build()) {
            
            ListTrailsRequest trailsRequest = ListTrailsRequest.builder().build();
            ListTrailsResponse trailsResponse = cloudTrailClient.listTrails(trailsRequest);
            
            if (trailsResponse.trails().isEmpty()) {
                Map<String, Object> vuln = new HashMap<>();
                vuln.put("type", "CloudTrail Not Configured");
                vuln.put("severity", "High");
                vuln.put("resource", "cloudtrail");
                vuln.put("evidence", "No CloudTrail trails found - API activity is not being logged");
                vulnerabilities.add(vuln);
                System.out.println("    [!] CloudTrail is not configured");
            } else {
                for (Trail trail : trailsResponse.trails()) {
                    GetTrailStatusRequest statusRequest = GetTrailStatusRequest.builder()
                            .name(trail.name())
                            .build();
                    
                    GetTrailStatusResponse statusResponse = cloudTrailClient.getTrailStatus(statusRequest);
                    
                    if (!statusResponse.isLogging()) {
                        Map<String, Object> vuln = new HashMap<>();
                        vuln.put("type", "CloudTrail Not Logging");
                        vuln.put("severity", "High");
                        vuln.put("resource", "cloudtrail:" + trail.name());
                        vuln.put("evidence", "CloudTrail trail exists but logging is disabled");
                        vulnerabilities.add(vuln);
                        System.out.println("    [!] CloudTrail " + trail.name() + " is not logging");
                    }
                }
            }
            
        } catch (Exception e) {
            System.out.println("  [!] Error checking CloudTrail: " + e.getMessage());
            System.out.println("  [!] Make sure you have cloudtrail:ListTrails permission");
        }
    }
    
    /**
     * Scan Lambda functions for security issues
     */
    public void scanLambdaFunctions() {
        System.out.println("\n[+] Scanning Lambda functions...");
        
        try (LambdaClient lambdaClient = LambdaClient.builder()
                .region(awsRegion)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build()) {
            
            ListFunctionsRequest functionsRequest = ListFunctionsRequest.builder().build();
            ListFunctionsResponse functionsResponse = lambdaClient.listFunctions(functionsRequest);
            
            for (FunctionConfiguration function : functionsResponse.functions()) {
                // Check if VPC configuration exists (may indicate network isolation)
                if (function.vpcConfig() == null || function.vpcConfig().vpcId() == null) {
                    Map<String, Object> vuln = new HashMap<>();
                    vuln.put("type", "Lambda Function Not in VPC");
                    vuln.put("severity", "Low");
                    vuln.put("resource", "lambda:" + function.functionName());
                    vuln.put("evidence", "Lambda function is not in a VPC - may have direct internet access");
                    vulnerabilities.add(vuln);
                    System.out.println("    [!] Lambda function " + function.functionName() + " not in VPC");
                }
            }
            
        } catch (Exception e) {
            System.out.println("  [!] Error scanning Lambda functions: " + e.getMessage());
            System.out.println("  [!] Make sure you have lambda:ListFunctions permission");
        }
    }
    
    /**
     * Run all AWS security scans
     */
    public List<Map<String, Object>> scan() {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("AWS Security VAPT Scan: " + region);
        System.out.println("=".repeat(60));
        
        System.out.println("\n[+] Starting AWS security scan...");
        
        checkAccountIdentity();
        scanS3Buckets();
        scanIAMPolicies();
        scanEC2SecurityGroups();
        scanRDSInstances();
        checkCloudTrail();
        scanLambdaFunctions();
        
        System.out.println("\n" + "=".repeat(60));
        System.out.println("Scan Complete!");
        System.out.println("Total vulnerabilities found: " + vulnerabilities.size());
        System.out.println("=".repeat(60) + "\n");
        
        return vulnerabilities;
    }
}
