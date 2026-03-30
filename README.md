# Warden IAM Security Remediation System

An automated IAM security remediation system that monitors CloudTrail events via EventBridge and quarantines suspicious IAM principals in real-time.

## Architecture Overview

This system implements event-driven security automation with the following flow:

1. **CloudTrail** captures AWS API calls
2. **EventBridge** filters for suspicious events (DeleteBucket, AttachUserPolicy, CreateAccessKey)
3. **Lambda** function processes events and:
   - Attaches a deny-all quarantine policy to the offending IAM principal
   - Sends detailed alerts via SNS
   - Logs all actions to CloudWatch
4. **SNS** delivers email notifications to security team
5. **Dead Letter Queue** captures failed Lambda invocations for investigation

## Components

### IAM Quarantine Policy
- **Name**: `warden-quarantine-deny-all`
- **Purpose**: Comprehensive deny-all policy that blocks all AWS actions
- **Pattern**: Based on AWS CompromisedKeyQuarantine policies
- **Scope**: Denies IAM privilege escalation, compute operations, and data exfiltration

### SNS Topic
- **Name**: `warden-security-alerts`
- **Encryption**: KMS-encrypted for security
- **Subscription**: Email notifications to configured address

### Lambda Function
- **Name**: `warden-quarantine-lambda`
- **Runtime**: Python 3.11
- **Features**:
  - Parses CloudTrail events from EventBridge
  - Extracts IAM principal (User/Role) from event details
  - Attaches quarantine policy idempotently
  - Comprehensive error handling and CloudWatch logging
  - Detailed SNS notifications with remediation guidance

### IAM Role
- **Name**: `warden-lambda-execution-role`
- **Permissions**: Least-privilege access to:
  - Attach policies to IAM users/roles (scoped to quarantine policy only)
  - Publish to SNS topic
  - Write to CloudWatch Logs
  - Send messages to DLQ

### EventBridge Rule
- **Name**: `warden-cloudtrail-monitor`
- **Triggers**: CloudTrail events matching:
  - `s3:DeleteBucket`
  - `iam:AttachUserPolicy`
  - `iam:CreateAccessKey`

## Deployment

### Prerequisites
- Terraform >= 1.0
- AWS CLI configured with credentials
- CloudTrail enabled in your AWS account

### Steps

1. **Package the Lambda function**:
```bash
chmod +x package_lambda.sh
./package_lambda.sh
```

2. **Initialize Terraform**:
```bash
terraform init
```

3. **Review the plan**:
```bash
terraform plan
```

4. **Deploy the infrastructure**:
```bash
terraform apply
```

5. **Confirm SNS subscription**:
   - Check your email for an SNS subscription confirmation
   - Click the confirmation link to start receiving alerts

## Configuration

### Variables

Edit `variables.tf` or create a `terraform.tfvars` file:

```hcl
region             = "us-east-1"
notification_email = "your-email@example.com"
```

### Customizing Monitored Events

To add or modify monitored CloudTrail events, edit the `event_pattern` in the `aws_cloudwatch_event_rule.warden_cloudtrail_monitor` resource in `main.tf`:

```hcl
event_pattern = jsonencode({
  source      = ["aws.s3", "aws.iam", "aws.ec2"]
  detail-type = ["AWS API Call via CloudTrail"]
  detail = {
    eventName = [
      "DeleteBucket",
      "AttachUserPolicy",
      "CreateAccessKey",
      "RunInstances"  # Add new events here
    ]
  }
})
```

## Testing

### Simulate a Suspicious Event

Create a test IAM user and trigger a monitored event:

```bash
# Create test user
aws iam create-user --user-name test-suspicious-user

# Trigger suspicious event (CreateAccessKey)
aws iam create-access-key --user-name test-suspicious-user
```

Within seconds, you should:
1. See Lambda execution in CloudWatch Logs (`/aws/lambda/warden-quarantine-lambda`)
2. Receive an email alert with quarantine details
3. Verify the quarantine policy is attached:
```bash
aws iam list-attached-user-policies --user-name test-suspicious-user
```

### Review CloudWatch Logs

```bash
aws logs tail /aws/lambda/warden-quarantine-lambda --follow
```

## Remediation

If a principal was quarantined legitimately, detach the policy:

**For IAM Users**:
```bash
aws iam detach-user-policy \
  --user-name <username> \
  --policy-arn $(terraform output -raw quarantine_policy_arn)
```

**For IAM Roles**:
```bash
aws iam detach-role-policy \
  --role-name <rolename> \
  --policy-arn $(terraform output -raw quarantine_policy_arn)
```

## Monitoring

### CloudWatch Metrics
- Lambda invocations: `AWS/Lambda` - `warden-quarantine-lambda`
- Lambda errors: Check CloudWatch Logs for stack traces
- DLQ messages: Monitor SQS queue `warden-lambda-dlq` for failed invocations

### SNS Alert Contents
Each alert includes:
- Event details (name, time, source, region, IP)
- Principal information (type, name, ARN, account)
- Quarantine action result
- Remediation instructions

## Security Considerations

⚠️ **Important Notes**:
- This is a **prototype for learning** - not production-ready
- The quarantine policy is extremely restrictive (denies ALL actions)
- Root account activities are intentionally excluded from quarantine
- EventBridge rules should be tuned to reduce false positives
- Consider adding approval workflows for production use
- Monitor the DLQ for failed quarantine attempts

## Cleanup

To remove all resources:

```bash
terraform destroy
```

**Note**: Manually detach the quarantine policy from any principals before destroying, or the destroy will fail.

## Outputs

After deployment, Terraform provides:
- `quarantine_policy_arn`: ARN of the deny-all quarantine policy
- `sns_topic_arn`: ARN of the security alerts topic
- `lambda_function_arn`: ARN of the quarantine Lambda
- `eventbridge_rule_arn`: ARN of the CloudTrail monitoring rule
- `dlq_url`: URL of the dead letter queue
- `cloudwatch_log_group`: Log group name for Lambda

## References

- [AWS Security Blog: Event-Driven Security Automation](https://aws.amazon.com/blogs/security/how-get-started-security-response-automation-aws/)
- [AWS EventBridge Security Best Practices](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-security.html)
- [AWS IAM CompromisedKeyQuarantine Policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html)

## License

This is a learning prototype - use at your own risk.
