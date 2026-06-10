# CloudWatch Log Metric Filters & Alarms
## CIS AWS Foundations Benchmark v1.4.0 — Security Hub Remediation

**Account ID:** 160884803568  
**Region:** ap-south-1 (Mumbai)  
**CloudTrail Log Group:** `CLoudtrail-logs`  
**Metric Namespace:** `LogMetrics`  
**SNS Topic ARN:** `arn:aws:sns:ap-south-1:160884803568:ec2-ops-alerts`  
**Prepared by:** Dixit Infotect — Cloud Department

---

## Overview

This document covers the AWS CLI commands to create **CloudWatch Log Metric Filters** and **CloudWatch Alarms** for all CIS AWS Foundations Benchmark v1.4.0 CloudWatch controls as required by AWS Security Hub CSPM.

Each control requires:
1. A **CloudWatch Log Metric Filter** on the CloudTrail log group to detect specific API events
2. A **CloudWatch Alarm** on the metric to trigger an **SNS notification** when the threshold is breached

> **Important:** AWS Security Hub checks specifically for metric namespace `LogMetrics`. Using any other namespace (e.g. `CISBenchmark`) will cause the Security Hub finding to remain `FAILED`.

---

## Controls Covered

| Control ID | CIS Section | Description |
|---|---|---|
| CloudWatch.1 | 1.7 / 4.3 | Root user usage |
| CloudWatch.4 | 4.4 | IAM policy changes |
| CloudWatch.5 | 4.5 | CloudTrail configuration changes |
| CloudWatch.6 | 4.6 | Console authentication failures |
| CloudWatch.7 | 4.7 | CMK disable or scheduled deletion |
| CloudWatch.8 | 4.8 | S3 bucket policy changes |
| CloudWatch.10 | 4.10 | Security group changes |
| CloudWatch.11 | 4.11 | NACL changes |
| CloudWatch.12 | 4.12 | Network gateway changes |
| CloudWatch.13 | 4.13 | Route table changes |
| CloudWatch.14 | 4.14 | VPC changes |

---

## Common Parameters

| Parameter | Value |
|---|---|
| Log Group Name | `CLoudtrail-logs` |
| Metric Namespace | `LogMetrics` |
| Metric Value | `1` |
| Default Value | `0` |
| Alarm Period | `300 seconds (5 minutes)` |
| Evaluation Periods | `1` |
| Threshold | `1` |
| Comparison Operator | `GreaterThanOrEqualToThreshold` |
| Treat Missing Data | `notBreaching` |
| SNS Topic | `arn:aws:sns:ap-south-1:160884803568:ec2-ops-alerts` |

---

## CloudWatch.1 — Root User Usage

**CIS Control:** 1.7 / 4.3  
**Description:** Detects any usage of the AWS root account user, which should be avoided for day-to-day operations.

```bash
# Step 1 — Create Metric Filter
aws logs put-metric-filter \
  --log-group-name "CLoudtrail-logs" \
  --filter-name "RootUserUsage" \
  --filter-pattern '{$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !="AwsServiceEvent"}' \
  --metric-transformations \
    metricName=RootUserUsageCount,metricNamespace=LogMetrics,metricValue=1,defaultValue=0 \
  --region ap-south-1

# Step 2 — Create CloudWatch Alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "CIS-RootUserUsage" \
  --alarm-description "Alarm for root user account usage" \
  --metric-name RootUserUsageCount \
  --namespace LogMetrics \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:sns:ap-south-1:160884803568:ec2-ops-alerts \
  --treat-missing-data notBreaching \
  --region ap-south-1
```

---

## CloudWatch.4 — IAM Policy Changes

**CIS Control:** 4.4  
**Description:** Detects changes to IAM policies including creation, deletion, and attachment/detachment of policies to users, groups, and roles.

> **Note:** The `$.eventSource=iam.amazonaws.com` condition is mandatory as per AWS Security Hub documentation. Omitting it will cause the finding to remain FAILED.

```bash
# Step 1 — Create Metric Filter
aws logs put-metric-filter \
  --log-group-name "CLoudtrail-logs" \
  --filter-name "IAMPolicyChanges" \
  --filter-pattern '{($.eventSource=iam.amazonaws.com) && (($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy))}' \
  --metric-transformations \
    metricName=IAMPolicyChangesCount,metricNamespace=LogMetrics,metricValue=1,defaultValue=0 \
  --region ap-south-1

# Step 2 — Create CloudWatch Alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "CIS-IAMPolicyChanges" \
  --alarm-description "Alarm for IAM policy changes" \
  --metric-name IAMPolicyChangesCount \
  --namespace LogMetrics \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:sns:ap-south-1:160884803568:ec2-ops-alerts \
  --treat-missing-data notBreaching \
  --region ap-south-1
```

---

## CloudWatch.5 — CloudTrail Configuration Changes

**CIS Control:** 4.5  
**Description:** Detects any changes to CloudTrail configuration including creating, updating, deleting trails, or starting/stopping logging.

```bash
# Step 1 — Create Metric Filter
aws logs put-metric-filter \
  --log-group-name "CLoudtrail-logs" \
  --filter-name "CloudTrailConfigChanges" \
  --filter-pattern '{($.eventName=CreateTrail)||($.eventName=UpdateTrail)||($.eventName=DeleteTrail)||($.eventName=StartLogging)||($.eventName=StopLogging)}' \
  --metric-transformations \
    metricName=CloudTrailConfigChangesCount,metricNamespace=LogMetrics,metricValue=1,defaultValue=0 \
  --region ap-south-1

# Step 2 — Create CloudWatch Alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "CIS-CloudTrailConfigChanges" \
  --alarm-description "Alarm for CloudTrail configuration changes" \
  --metric-name CloudTrailConfigChangesCount \
  --namespace LogMetrics \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:sns:ap-south-1:160884803568:ec2-ops-alerts \
  --treat-missing-data notBreaching \
  --region ap-south-1
```

---

## CloudWatch.6 — Console Authentication Failures

**CIS Control:** 4.6  
**Description:** Detects failed AWS Management Console login attempts. Helps identify brute-force credential attacks.

```bash
# Step 1 — Create Metric Filter
aws logs put-metric-filter \
  --log-group-name "CLoudtrail-logs" \
  --filter-name "ConsoleAuthFailures" \
  --filter-pattern '{($.eventName=ConsoleLogin)&&($.errorMessage="Failed authentication")}' \
  --metric-transformations \
    metricName=ConsoleAuthFailuresCount,metricNamespace=LogMetrics,metricValue=1,defaultValue=0 \
  --region ap-south-1

# Step 2 — Create CloudWatch Alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "CIS-ConsoleAuthFailures" \
  --alarm-description "Alarm for console authentication failures" \
  --metric-name ConsoleAuthFailuresCount \
  --namespace LogMetrics \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:sns:ap-south-1:160884803568:ec2-ops-alerts \
  --treat-missing-data notBreaching \
  --region ap-south-1
```

---

## CloudWatch.7 — CMK Disable or Scheduled Deletion

**CIS Control:** 4.7  
**Description:** Detects when a Customer Managed Key (CMK) in AWS KMS is disabled or scheduled for deletion. Data encrypted with disabled/deleted keys becomes inaccessible.

```bash
# Step 1 — Create Metric Filter
aws logs put-metric-filter \
  --log-group-name "CLoudtrail-logs" \
  --filter-name "CMKDisableOrDelete" \
  --filter-pattern '{($.eventSource=kms.amazonaws.com)&&(($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion))}' \
  --metric-transformations \
    metricName=CMKDisableOrDeleteCount,metricNamespace=LogMetrics,metricValue=1,defaultValue=0 \
  --region ap-south-1

# Step 2 — Create CloudWatch Alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "CIS-CMKDisableOrDelete" \
  --alarm-description "Alarm for CMK disable or scheduled deletion" \
  --metric-name CMKDisableOrDeleteCount \
  --namespace LogMetrics \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:sns:ap-south-1:160884803568:ec2-ops-alerts \
  --treat-missing-data notBreaching \
  --region ap-south-1
```

---

## CloudWatch.8 — S3 Bucket Policy Changes

**CIS Control:** 4.8  
**Description:** Detects changes to S3 bucket policies, ACLs, CORS, lifecycle, and replication configurations. Helps identify permissive policy changes on sensitive buckets.

```bash
# Step 1 — Create Metric Filter
aws logs put-metric-filter \
  --log-group-name "CLoudtrail-logs" \
  --filter-name "S3BucketPolicyChanges" \
  --filter-pattern '{($.eventSource=s3.amazonaws.com)&&(($.eventName=PutBucketAcl)||($.eventName=PutBucketPolicy)||($.eventName=PutBucketCors)||($.eventName=PutBucketLifecycle)||($.eventName=PutBucketReplication)||($.eventName=DeleteBucketPolicy)||($.eventName=DeleteBucketCors)||($.eventName=DeleteBucketLifecycle)||($.eventName=DeleteBucketReplication))}' \
  --metric-transformations \
    metricName=S3BucketPolicyChangesCount,metricNamespace=LogMetrics,metricValue=1,defaultValue=0 \
  --region ap-south-1

# Step 2 — Create CloudWatch Alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "CIS-S3BucketPolicyChanges" \
  --alarm-description "Alarm for S3 bucket policy changes" \
  --metric-name S3BucketPolicyChangesCount \
  --namespace LogMetrics \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:sns:ap-south-1:160884803568:ec2-ops-alerts \
  --treat-missing-data notBreaching \
  --region ap-south-1
```

---

## CloudWatch.10 — Security Group Changes

**CIS Control:** 4.10  
**Description:** Detects changes to VPC Security Groups including ingress/egress rule modifications and security group creation/deletion. Security Groups act as stateful packet filters controlling VPC traffic.

```bash
# Step 1 — Create Metric Filter
aws logs put-metric-filter \
  --log-group-name "CLoudtrail-logs" \
  --filter-name "SecurityGroupChanges" \
  --filter-pattern '{($.eventName=AuthorizeSecurityGroupIngress)||($.eventName=AuthorizeSecurityGroupEgress)||($.eventName=RevokeSecurityGroupIngress)||($.eventName=RevokeSecurityGroupEgress)||($.eventName=CreateSecurityGroup)||($.eventName=DeleteSecurityGroup)}' \
  --metric-transformations \
    metricName=SecurityGroupChangesCount,metricNamespace=LogMetrics,metricValue=1,defaultValue=0 \
  --region ap-south-1

# Step 2 — Create CloudWatch Alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "CIS-SecurityGroupChanges" \
  --alarm-description "Alarm for security group changes" \
  --metric-name SecurityGroupChangesCount \
  --namespace LogMetrics \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:sns:ap-south-1:160884803568:ec2-ops-alerts \
  --treat-missing-data notBreaching \
  --region ap-south-1
```

---

## CloudWatch.11 — NACL Changes

**CIS Control:** 4.11  
**Description:** Detects changes to Network Access Control Lists (NACLs). NACLs are stateless packet filters that control ingress and egress traffic at the subnet level within a VPC.

```bash
# Step 1 — Create Metric Filter
aws logs put-metric-filter \
  --log-group-name "CLoudtrail-logs" \
  --filter-name "NACLChanges" \
  --filter-pattern '{($.eventName=CreateNetworkAcl)||($.eventName=CreateNetworkAclEntry)||($.eventName=DeleteNetworkAcl)||($.eventName=DeleteNetworkAclEntry)||($.eventName=ReplaceNetworkAclEntry)||($.eventName=ReplaceNetworkAclAssociation)}' \
  --metric-transformations \
    metricName=NACLChangesCount,metricNamespace=LogMetrics,metricValue=1,defaultValue=0 \
  --region ap-south-1

# Step 2 — Create CloudWatch Alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "CIS-NACLChanges" \
  --alarm-description "Alarm for NACL changes" \
  --metric-name NACLChangesCount \
  --namespace LogMetrics \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:sns:ap-south-1:160884803568:ec2-ops-alerts \
  --treat-missing-data notBreaching \
  --region ap-south-1
```

---

## CloudWatch.12 — Network Gateway Changes

**CIS Control:** 4.12  
**Description:** Detects changes to network gateways including Internet Gateways and Customer Gateways. Network gateways control all traffic entering and exiting a VPC boundary.

```bash
# Step 1 — Create Metric Filter
aws logs put-metric-filter \
  --log-group-name "CLoudtrail-logs" \
  --filter-name "NetworkGatewayChanges" \
  --filter-pattern '{($.eventName=CreateCustomerGateway)||($.eventName=DeleteCustomerGateway)||($.eventName=AttachInternetGateway)||($.eventName=CreateInternetGateway)||($.eventName=DeleteInternetGateway)||($.eventName=DetachInternetGateway)}' \
  --metric-transformations \
    metricName=NetworkGatewayChangesCount,metricNamespace=LogMetrics,metricValue=1,defaultValue=0 \
  --region ap-south-1

# Step 2 — Create CloudWatch Alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "CIS-NetworkGatewayChanges" \
  --alarm-description "Alarm for network gateway changes" \
  --metric-name NetworkGatewayChangesCount \
  --namespace LogMetrics \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:sns:ap-south-1:160884803568:ec2-ops-alerts \
  --treat-missing-data notBreaching \
  --region ap-south-1
```

---

## CloudWatch.13 — Route Table Changes

**CIS Control:** 4.13  
**Description:** Detects changes to VPC Route Tables. Route tables control the routing of network traffic between subnets and to network gateways within a VPC.

> **Note:** The `$.eventSource=ec2.amazonaws.com` condition is mandatory as per AWS Security Hub documentation. Omitting it will cause the finding to remain FAILED.

```bash
# Step 1 — Create Metric Filter
aws logs put-metric-filter \
  --log-group-name "CLoudtrail-logs" \
  --filter-name "RouteTableChanges" \
  --filter-pattern '{($.eventSource=ec2.amazonaws.com)&&(($.eventName=CreateRoute)||($.eventName=CreateRouteTable)||($.eventName=ReplaceRoute)||($.eventName=ReplaceRouteTableAssociation)||($.eventName=DeleteRouteTable)||($.eventName=DeleteRoute)||($.eventName=DisassociateRouteTable))}' \
  --metric-transformations \
    metricName=RouteTableChangesCount,metricNamespace=LogMetrics,metricValue=1,defaultValue=0 \
  --region ap-south-1

# Step 2 — Create CloudWatch Alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "CIS-RouteTableChanges" \
  --alarm-description "Alarm for route table changes" \
  --metric-name RouteTableChangesCount \
  --namespace LogMetrics \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:sns:ap-south-1:160884803568:ec2-ops-alerts \
  --treat-missing-data notBreaching \
  --region ap-south-1
```

---

## CloudWatch.14 — VPC Changes

**CIS Control:** 4.14  
**Description:** Detects changes to VPCs including creation, deletion, attribute modifications, and VPC peering connection changes.

```bash
# Step 1 — Create Metric Filter
aws logs put-metric-filter \
  --log-group-name "CLoudtrail-logs" \
  --filter-name "VPCChanges" \
  --filter-pattern '{($.eventName=CreateVpc)||($.eventName=DeleteVpc)||($.eventName=ModifyVpcAttribute)||($.eventName=AcceptVpcPeeringConnection)||($.eventName=CreateVpcPeeringConnection)||($.eventName=DeleteVpcPeeringConnection)||($.eventName=RejectVpcPeeringConnection)||($.eventName=AttachClassicLinkVpc)||($.eventName=DetachClassicLinkVpc)||($.eventName=DisableVpcClassicLink)||($.eventName=EnableVpcClassicLink)}' \
  --metric-transformations \
    metricName=VPCChangesCount,metricNamespace=LogMetrics,metricValue=1,defaultValue=0 \
  --region ap-south-1

# Step 2 — Create CloudWatch Alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "CIS-VPCChanges" \
  --alarm-description "Alarm for VPC changes" \
  --metric-name VPCChangesCount \
  --namespace LogMetrics \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:sns:ap-south-1:160884803568:ec2-ops-alerts \
  --treat-missing-data notBreaching \
  --region ap-south-1
```

---

## Verification Commands

### Verify All Metric Filters
```bash
aws logs describe-metric-filters \
  --log-group-name "CLoudtrail-logs" \
  --region ap-south-1 \
  --query 'metricFilters[*].[filterName,metricTransformations[0].metricNamespace]' \
  --output table
```

### Verify All CloudWatch Alarms
```bash
aws cloudwatch describe-alarms \
  --alarm-name-prefix "CIS-" \
  --region ap-south-1 \
  --query 'MetricAlarms[*].[AlarmName,StateValue,Namespace]' \
  --output table
```

### Verify Alarm SNS Actions
```bash
aws cloudwatch describe-alarms \
  --alarm-name-prefix "CIS-" \
  --region ap-south-1 \
  --query 'MetricAlarms[*].[AlarmName,AlarmActions]' \
  --output table
```

### Check Security Hub CIS Findings Status
```bash
aws securityhub get-findings \
  --filters '{
    "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
    "ProductName": [{"Value": "Security Hub", "Comparison": "EQUALS"}],
    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
    "Title": [{"Value": "CloudWatch", "Comparison": "PREFIX"}]
  }' \
  --region ap-south-1 \
  --query 'Findings[*].[ProductFields.ControlId,Title,Compliance.Status,UpdatedAt]' \
  --output table
```

---

## Expected Verification Output

### Metric Filters (Expected)
```
-------------------------------------------
|          DescribeMetricFilters          |
+--------------------------+--------------+
|  CMKDisableOrDelete      |  LogMetrics  |
|  CloudTrailConfigChanges |  LogMetrics  |
|  ConsoleAuthFailures     |  LogMetrics  |
|  IAMPolicyChanges        |  LogMetrics  |
|  NACLChanges             |  LogMetrics  |
|  NetworkGatewayChanges   |  LogMetrics  |
|  RootUserUsage           |  LogMetrics  |
|  RouteTableChanges       |  LogMetrics  |
|  S3BucketPolicyChanges   |  LogMetrics  |
|  SecurityGroupChanges    |  LogMetrics  |
|  VPCChanges              |  LogMetrics  |
+--------------------------+--------------+
```

### CloudWatch Alarms (Expected)
```
-----------------------------------------------------
|                  DescribeAlarms                   |
+------------------------------+-----+--------------+
|  CIS-CMKDisableOrDelete      |  OK |  LogMetrics  |
|  CIS-CloudTrailConfigChanges |  OK |  LogMetrics  |
|  CIS-ConsoleAuthFailures     |  OK |  LogMetrics  |
|  CIS-IAMPolicyChanges        |  OK |  LogMetrics  |
|  CIS-NACLChanges             |  OK |  LogMetrics  |
|  CIS-NetworkGatewayChanges   |  OK |  LogMetrics  |
|  CIS-RootUserUsage           |  OK |  LogMetrics  |
|  CIS-RouteTableChanges       |  OK |  LogMetrics  |
|  CIS-S3BucketPolicyChanges   |  OK |  LogMetrics  |
|  CIS-SecurityGroupChanges    |  OK |  LogMetrics  |
|  CIS-VPCChanges              |  OK |  LogMetrics  |
+------------------------------+-----+--------------+
```

---

## Key Notes

| Topic | Detail |
|---|---|
| **Metric Namespace** | Must be `LogMetrics` — Security Hub checks for this exact namespace |
| **put-metric-filter behavior** | Upsert operation — re-running updates existing filter, no duplicates created |
| **put-metric-alarm behavior** | Upsert operation — re-running updates existing alarm, no duplicates created |
| **Alarm OK state** | Expected healthy state — means no alarm condition is currently triggered |
| **treat-missing-data notBreaching** | Prevents alarms from entering INSUFFICIENT_DATA state during periods of no activity |
| **Security Hub evaluation** | Periodic schedule — findings update to PASSED within 12–24 hours after correct configuration |
| **CloudWatch.4 filter** | Requires `$.eventSource=iam.amazonaws.com` wrapper condition |
| **CloudWatch.13 filter** | Requires `$.eventSource=ec2.amazonaws.com` wrapper condition |

---

## Reference

- [AWS Security Hub CloudWatch Controls Documentation](https://docs.aws.amazon.com/securityhub/latest/userguide/cloudwatch-controls.html)
- [CIS AWS Foundations Benchmark v1.4.0](https://www.cisecurity.org/benchmark/amazon_web_services)
- [CloudWatch Metric Filters — AWS Documentation](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CreateMetricFilterProcedure.html)
- [CloudWatch Alarms — AWS Documentation](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html)
