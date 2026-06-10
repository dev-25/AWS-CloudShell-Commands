# AWS Inspector Findings Alert — EventBridge → Lambda → CloudWatch Logs

## Overview

This guide sets up an automated alerting pipeline that triggers whenever **AWS Inspector v2** generates a new finding. The finding details are captured in **structured JSON format** and stored in **Amazon CloudWatch Logs** for monitoring and SIEM integration (e.g., IBM QRadar).

---

## Architecture

```
AWS Inspector v2 (New Finding)
        │
        ▼
Amazon EventBridge Rule
(source: aws.inspector2 | detail-type: Inspector2 Finding)
        │
        ▼
AWS Lambda Function
(inspector-findings-alert | Python 3.12)
        │
        ▼
Amazon CloudWatch Log Group
(/aws/lambda/inspector-findings-alert)
[Structured JSON per finding]
```

---

## Prerequisites

- AWS CLI configured (or AWS CloudShell access)
- Region: `ap-south-1` (Mumbai)
- AWS Inspector v2 enabled in your account
- IAM permissions: `iam:CreateRole`, `lambda:CreateFunction`, `events:PutRule`, `logs:CreateLogGroup`

> **Note:** If your account has a **VPC Endpoint Policy** on `com.amazonaws.ap-south-1.logs` that restricts `logs:CreateLogGroup`, skip **Step 1** — Lambda will auto-create the log group on first invocation.

---

## Setup Steps

### Step 1 — Create CloudWatch Log Group (Optional)

> Skip this step if you hit `AccessDeniedException` due to VPC Endpoint Policy restrictions. Lambda auto-creates the log group on first invocation.

```bash
aws logs create-log-group \
  --log-group-name /aws/lambda/inspector-findings-alert \
  --region ap-south-1
```

---

### Step 2 — Create IAM Execution Role for Lambda

**Create the trust policy document:**

```bash
cat > /tmp/lambda-trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
```

**Create the IAM Role:**

```bash
aws iam create-role \
  --role-name inspector-findings-lambda-role \
  --assume-role-policy-document file:///tmp/lambda-trust-policy.json
```

**Attach AWS managed policy for CloudWatch Logs access:**

```bash
aws iam attach-role-policy \
  --role-name inspector-findings-lambda-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
```

> ⏳ Wait **10–15 seconds** for IAM role propagation before proceeding to Lambda creation.

---

### Step 3 — Create Lambda Function Code

```bash
cat > /tmp/inspector_alert.py << 'EOF'
import json
import logging
import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    try:
        # Extract Inspector finding details from EventBridge event
        detail = event.get("detail", {})

        finding_output = {
            "alert_type": "AWS_INSPECTOR_NEW_FINDING",
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "finding_arn": detail.get("findingArn", "N/A"),
            "severity": detail.get("severity", "N/A"),
            "title": detail.get("title", "N/A"),
            "description": detail.get("description", "N/A"),
            "status": detail.get("status", "N/A"),
            "type": detail.get("type", "N/A"),
            "first_observed": detail.get("firstObservedAt", "N/A"),
            "last_observed": detail.get("lastObservedAt", "N/A"),
            "remediation": detail.get("remediation", {}).get("recommendation", {}).get("text", "N/A"),
            "affected_resource": {
                "type": detail.get("resources", [{}])[0].get("type", "N/A"),
                "id": detail.get("resources", [{}])[0].get("id", "N/A"),
                "region": detail.get("resources", [{}])[0].get("region", "N/A"),
                "account_id": event.get("account", "N/A")
            },
            "inspector_score": detail.get("inspectorScore", "N/A"),
            "aws_account_id": event.get("account", "N/A"),
            "aws_region": event.get("region", "N/A"),
            "raw_event": event
        }

        # Log structured JSON to CloudWatch Logs
        logger.info(json.dumps(finding_output, indent=2, default=str))

        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "Inspector finding logged successfully",
                "finding_arn": finding_output["finding_arn"]
            })
        }

    except Exception as e:
        logger.error(json.dumps({
            "error": str(e),
            "raw_event": event
        }, default=str))
        raise
EOF
```

**Package the Lambda deployment zip:**

```bash
cd /tmp && zip inspector_alert.zip inspector_alert.py
```

---

### Step 4 — Deploy Lambda Function

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

aws lambda create-function \
  --function-name inspector-findings-alert \
  --runtime python3.12 \
  --role arn:aws:iam::${ACCOUNT_ID}:role/inspector-findings-lambda-role \
  --handler inspector_alert.lambda_handler \
  --zip-file fileb:///tmp/inspector_alert.zip \
  --timeout 30 \
  --memory-size 128 \
  --region ap-south-1
```

---

### Step 5 — Create EventBridge Rule

```bash
aws events put-rule \
  --name inspector-new-findings-rule \
  --event-pattern '{
    "source": ["aws.inspector2"],
    "detail-type": ["Inspector2 Finding"]
  }' \
  --state ENABLED \
  --description "Triggers Lambda on every new AWS Inspector v2 finding" \
  --region ap-south-1
```

---

### Step 6 — Grant EventBridge Permission to Invoke Lambda

```bash
aws lambda add-permission \
  --function-name inspector-findings-alert \
  --statement-id eventbridge-inspector-invoke \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn arn:aws:events:ap-south-1:${ACCOUNT_ID}:rule/inspector-new-findings-rule \
  --region ap-south-1
```

---

### Step 7 — Add Lambda as EventBridge Target

```bash
aws events put-targets \
  --rule inspector-new-findings-rule \
  --targets '[
    {
      "Id": "inspector-lambda-target",
      "Arn": "arn:aws:lambda:ap-south-1:'${ACCOUNT_ID}':function:inspector-findings-alert"
    }
  ]' \
  --region ap-south-1
```

---

## Verification

### Check EventBridge Rule State

```bash
aws events describe-rule \
  --name inspector-new-findings-rule \
  --region ap-south-1
```

### Check Lambda Targets on the Rule

```bash
aws events list-targets-by-rule \
  --rule inspector-new-findings-rule \
  --region ap-south-1
```

### Check Lambda Function Status

```bash
aws lambda get-function \
  --function-name inspector-findings-alert \
  --region ap-south-1 \
  --query 'Configuration.[FunctionName,Runtime,State,LastModified]'
```

---

## Test — Invoke Lambda with Simulated Inspector Event

```bash
aws lambda invoke \
  --function-name inspector-findings-alert \
  --region ap-south-1 \
  --payload '{
    "version": "0",
    "id": "test-event-001",
    "source": "aws.inspector2",
    "account": "'${ACCOUNT_ID}'",
    "region": "ap-south-1",
    "detail-type": "Inspector2 Finding",
    "detail": {
      "findingArn": "arn:aws:inspector2:ap-south-1:'${ACCOUNT_ID}':finding/test-finding-001",
      "severity": "HIGH",
      "title": "Test Finding - CVE-2024-1234",
      "description": "This is a simulated Inspector finding for testing",
      "status": "ACTIVE",
      "type": "PACKAGE_VULNERABILITY",
      "inspectorScore": 8.5,
      "firstObservedAt": "2026-06-09T00:00:00Z",
      "lastObservedAt": "2026-06-09T12:00:00Z",
      "remediation": {
        "recommendation": {
          "text": "Update the affected package to the latest version"
        }
      },
      "resources": [
        {
          "type": "AWS_EC2_INSTANCE",
          "id": "i-0123456789abcdef0",
          "region": "ap-south-1"
        }
      ]
    }
  }' \
  /tmp/lambda_test_output.json && cat /tmp/lambda_test_output.json
```

---

## View JSON Logs in CloudWatch

```bash
# Get the latest log stream name
LOG_STREAM=$(aws logs describe-log-streams \
  --log-group-name /aws/lambda/inspector-findings-alert \
  --order-by LastEventTime \
  --descending \
  --limit 1 \
  --region ap-south-1 \
  --query 'logStreams[0].logStreamName' \
  --output text)

echo "Log Stream: $LOG_STREAM"

# Fetch and display log events
aws logs get-log-events \
  --log-group-name /aws/lambda/inspector-findings-alert \
  --log-stream-name "$LOG_STREAM" \
  --region ap-south-1 \
  --query 'events[*].message' \
  --output text
```

---

## Sample CloudWatch Log Output (JSON)

```json
{
  "alert_type": "AWS_INSPECTOR_NEW_FINDING",
  "timestamp": "2026-06-09T12:00:00Z",
  "finding_arn": "arn:aws:inspector2:ap-south-1:348784786562:finding/xxxxx",
  "severity": "HIGH",
  "title": "CVE-2024-1234 in libssl",
  "description": "A vulnerability was found in libssl package",
  "status": "ACTIVE",
  "type": "PACKAGE_VULNERABILITY",
  "inspector_score": 8.5,
  "first_observed": "2026-06-09T00:00:00Z",
  "last_observed": "2026-06-09T12:00:00Z",
  "remediation": "Update libssl to version 3.0.x or later",
  "affected_resource": {
    "type": "AWS_EC2_INSTANCE",
    "id": "i-0123456789abcdef0",
    "region": "ap-south-1",
    "account_id": "348784786562"
  },
  "aws_account_id": "348784786562",
  "aws_region": "ap-south-1"
}
```

---

## Troubleshooting

### AccessDeniedException on logs:CreateLogGroup

**Cause:** VPC Endpoint Policy on `com.amazonaws.ap-south-1.logs` is blocking the action.

**Fix Option 1 — Update VPC Endpoint Policy:**

```bash
# Get the endpoint ID
aws ec2 describe-vpc-endpoints \
  --filters "Name=service-name,Values=com.amazonaws.ap-south-1.logs" \
  --query 'VpcEndpoints[*].{ID:VpcEndpointId,State:State}' \
  --region ap-south-1

# Update the policy
aws ec2 modify-vpc-endpoint \
  --vpc-endpoint-id vpce-xxxxxxxxxxxxxxxxx \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow","Principal": "*","Action": "logs:*","Resource": "*"}]
  }' \
  --region ap-south-1
```

**Fix Option 2 — Skip log group creation:**
Lambda automatically creates the log group `/aws/lambda/inspector-findings-alert` on first invocation when `AWSLambdaBasicExecutionRole` is attached. Skip Step 1 and proceed directly.

---

### Lambda Not Triggering

- Verify EventBridge rule **State** is `ENABLED`
- Confirm Lambda **resource-based policy** has `events.amazonaws.com` as principal (Step 6)
- Check Lambda execution role has `logs:CreateLogStream` and `logs:PutLogEvents` permissions

---

### Inspector Findings Not Appearing

- Confirm **AWS Inspector v2** is enabled: `aws inspector2 get-member --account-id <id> --region ap-south-1`
- Inspector only generates `Inspector2 Finding` events for **EC2, ECR image, and Lambda** resources that are actively monitored

---

## Resources

| Resource | ARN / Name |
|---|---|
| Lambda Function | `inspector-findings-alert` |
| IAM Role | `inspector-findings-lambda-role` |
| EventBridge Rule | `inspector-new-findings-rule` |
| CloudWatch Log Group | `/aws/lambda/inspector-findings-alert` |
| AWS Region | `ap-south-1` |

---

## Export Type Clarification — SBOM Export vs Finding Alerts

| Feature | Behavior |
|---|---|
| **SBOM Export** (Inspector → S3) | One-time on-demand snapshot; must re-trigger manually or via EventBridge Scheduler + Lambda calling `CreateSbomExport` API |
| **Finding Alerts** (this guide) | Continuous — EventBridge triggers Lambda on **every new finding** in real time |
