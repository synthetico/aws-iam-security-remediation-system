# Warden System Testing Guide

## Overview

This guide provides step-by-step instructions for testing the Warden IAM Security Remediation System using both AWS CLI and AWS Console.

## Prerequisites

Before testing, ensure:

1. ✓ Terraform infrastructure is deployed: `terraform apply`
2. ✓ SNS email subscription is confirmed (check your email)
3. ✓ CloudTrail is enabled in your AWS account (required for EventBridge integration)
4. ✓ You have appropriate IAM permissions to create users and access keys

## Quick Test (Automated)

The fastest way to test the system:

```bash
chmod +x test-warden.sh
./test-warden.sh
```

This script will:
- Create a test user
- Trigger a suspicious CreateAccessKey event
- Monitor Lambda execution
- Verify quarantine policy attachment
- Clean up automatically

---

## Manual Testing via AWS Console

### Step 1: Verify Infrastructure Deployment

**Navigate to AWS Console**

1. **Lambda Console**: https://console.aws.amazon.com/lambda
   - Search for: `warden-quarantine-lambda`
   - Status should be: **Active**
   - Note the function ARN

2. **EventBridge Console**: https://console.aws.amazon.com/events
   - Navigate to: **Rules** → Select region: **us-east-1**
   - Search for: `warden-cloudtrail-monitor`
   - Status should be: **Enabled**
   - Click on the rule → **Targets** tab → Verify Lambda is listed

3. **SNS Console**: https://console.aws.amazon.com/sns
   - Navigate to: **Topics**
   - Search for: `warden-security-alerts`
   - Click **Subscriptions** tab
   - Verify your email is subscribed and **Status = Confirmed**

4. **IAM Console**: https://console.aws.amazon.com/iam
   - Navigate to: **Policies**
   - Search for: `warden-quarantine-deny-all`
   - Verify the policy exists

### Step 2: Create Test IAM User

**In IAM Console**:

1. Navigate to: **IAM** → **Users** → **Add users**
2. Configure user:
   - Username: `warden-test-user`
   - Select: **Programmatic access** (creates access key automatically - triggers Warden!)
   - **OR** just create the user without access key (you'll create it in Step 3)
3. Permissions: Skip (don't attach any permissions)
4. Tags (optional):
   - Key: `Purpose`, Value: `WardenTest`
   - Key: `AutoDelete`, Value: `true`
5. Click **Create user**

**Important**: If you selected "Programmatic access", the system will be triggered immediately when the access key is created. Skip to Step 4 to verify.

### Step 3: Trigger Suspicious Activity - CreateAccessKey Event

**Option A: Console (Recommended for visual testing)**

1. Navigate to: **IAM** → **Users** → Click `warden-test-user`
2. Go to: **Security credentials** tab
3. Scroll to: **Access keys** section
4. Click: **Create access key**
5. Select use case: **Command Line Interface (CLI)**
6. Check: "I understand..." → Click **Next**
7. Optional description: "Test key to trigger Warden"
8. Click: **Create access key**
9. 🚨 **SUSPICIOUS ACTIVITY TRIGGERED!**

**You should see**:
- Access key created successfully (AccessKeyId shown)
- **Within 10-30 seconds**, the Warden system will quarantine this user

**Option B: CloudShell or CLI**

If you prefer command line:

1. Navigate to: **CloudShell** (icon in top-right of AWS Console)
2. Run:
```bash
aws iam create-access-key --user-name warden-test-user
```

### Step 4: Monitor Lambda Execution (Real-time)

**CloudWatch Logs Console**:

1. Navigate to: **CloudWatch** → **Logs** → **Log groups**
2. Search for: `/aws/lambda/warden-quarantine-lambda`
3. Click on the log group
4. You should see a new **Log stream** (created within 10-30 seconds)
5. Click the newest log stream
6. Look for log entries:
   ```
   INFO Received event: {...}
   INFO Processing suspicious event 'CreateAccessKey' by user 'warden-test-user'
   INFO Successfully attached quarantine policy to user 'warden-test-user'
   INFO SNS notification sent successfully
   ```

**Tip**: Enable **Auto-refresh** (toggle at top-right) to see logs in real-time

### Step 5: Verify Quarantine Policy Attached

**Back in IAM Console**:

1. Navigate to: **IAM** → **Users** → Click `warden-test-user`
2. Go to: **Permissions** tab
3. Look in **Permissions policies** section
4. You should see: **warden-quarantine-deny-all** attached
5. Click on the policy to see the deny statements

**Expected result**: User now has the quarantine policy attached, denying all AWS actions.

### Step 6: Check Email Alert

**In your email inbox**:

1. Look for email from: **AWS Notifications** or your SNS topic
2. Subject: `WARDEN ALERT: CreateAccessKey - IAM Principal Quarantined`
3. Email body contains:
   - **EVENT DETAILS**: CreateAccessKey, timestamp, source IP
   - **PRINCIPAL INFORMATION**: User ARN, account ID
   - **QUARANTINE ACTION**: Policy attached successfully
   - **RECOMMENDED ACTIONS**: How to investigate and remediate

**If you don't see the email**:
- Check spam/junk folder
- Verify SNS subscription is confirmed (Step 1.3)
- Check SNS console for failed delivery attempts

### Step 7: Verify User is Actually Quarantined

**Test that the user cannot perform actions**:

**Option A: Console Test**

1. Still in IAM → Users → `warden-test-user`
2. Try to create another access key:
   - Click **Create access key** again
   - You should get: **Access Denied** or the action fails
3. Try to attach a policy:
   - Go to **Permissions** → **Add permissions**
   - Try to attach any policy
   - Should fail with access denied

**Option B: CLI Test (using CloudShell)**

```bash
# Try to create another access key (should fail)
aws iam create-access-key --user-name warden-test-user

# Expected error: "AccessDenied" or similar
```

### Step 8: Test Additional Suspicious Events

**Test AttachUserPolicy Event**:

1. Navigate to: **IAM** → **Users** → `warden-test-user`
2. Click: **Add permissions** → **Attach policies directly**
3. Select: **ReadOnlyAccess** policy
4. Click: **Next** → **Add permissions**
5. 🚨 **Another suspicious event triggered!**
6. Check CloudWatch logs again - you should see another Lambda invocation
7. Check email - you should receive another alert

**Note**: Since the user is already quarantined, this action may be denied by the quarantine policy itself.

---

## Monitoring and Observability

### CloudWatch Metrics

**Lambda Metrics**:
1. Navigate to: **CloudWatch** → **Metrics** → **All metrics**
2. Search: `warden-quarantine-lambda`
3. View metrics:
   - **Invocations**: Number of times Lambda was triggered
   - **Duration**: How long each execution took
   - **Errors**: Any failed executions
   - **Throttles**: If rate limits were hit

### Dead Letter Queue

**Check for failed invocations**:

1. Navigate to: **SQS** → **Queues**
2. Search for: `warden-lambda-dlq`
3. Click on the queue
4. Look at: **Messages available**
5. If > 0, click **Send and receive messages** → **Poll for messages**
6. Review any failed invocations to debug issues

### EventBridge Metrics

**Verify rule is processing events**:

1. Navigate to: **EventBridge** → **Rules**
2. Click: `warden-cloudtrail-monitor`
3. View: **Monitoring** tab
4. Check:
   - **Invocations**: Events matched and sent to Lambda
   - **Failed invocations**: Events that failed to trigger Lambda

---

## Testing Different Event Types

### Test 1: CreateAccessKey (Already tested above)
- **Trigger**: Create access key for IAM user
- **Risk**: Potential credential creation for unauthorized access

### Test 2: AttachUserPolicy (Privilege escalation)
- **Trigger**: Attach any policy to an IAM user
- **Risk**: Attacker granting themselves additional permissions

**How to test**:
1. Create a new test user: `warden-test-user-2`
2. Navigate to: IAM → Users → `warden-test-user-2`
3. Click: **Add permissions** → **Attach policies directly**
4. Select any policy (e.g., ReadOnlyAccess)
5. Click: **Add permissions**
6. 🚨 Triggers Warden → User quarantined

### Test 3: DeleteBucket (Data destruction)
- **Trigger**: Delete an S3 bucket
- **Risk**: Attacker destroying data or evidence

**How to test**:
1. Create a test S3 bucket: `warden-test-bucket-<random>`
2. Navigate to: **S3** → Select the bucket
3. Click: **Delete**
4. Confirm deletion
5. 🚨 Triggers Warden → User quarantined

**Note**: This will quarantine YOUR current user, so use a test IAM user with S3 permissions instead.

---

## Interpreting Results

### Success Indicators

✓ **Lambda executed successfully**
- CloudWatch logs show "Successfully attached quarantine policy"
- No errors in logs

✓ **Policy attached correctly**
- Quarantine policy visible in IAM user's permissions
- Policy attachment happened within 30 seconds of suspicious event

✓ **Email alert received**
- Email arrived within 1-2 minutes
- Contains accurate event details and remediation guidance

✓ **User is blocked**
- Subsequent actions by the user are denied
- Access keys become ineffective

### Troubleshooting

❌ **Lambda not invoked**
- **Check**: CloudTrail is enabled in the region
- **Check**: EventBridge rule is enabled
- **Check**: Event pattern matches the action you performed
- **Fix**: Verify CloudTrail logging is active: CloudTrail → Trails → Status

❌ **Lambda invoked but policy not attached**
- **Check**: CloudWatch logs for error messages
- **Check**: Lambda has IAM permissions to attach policies
- **Check**: User/role exists and is not a root account (root is excluded)
- **Fix**: Review Lambda execution role permissions

❌ **No email received**
- **Check**: SNS subscription status (should be "Confirmed")
- **Check**: Email not in spam folder
- **Check**: SNS topic permissions allow Lambda to publish
- **Fix**: Manually confirm subscription from SNS console

❌ **Dead Letter Queue has messages**
- **Meaning**: Lambda invocations failed repeatedly
- **Action**: Poll DLQ messages to see error details
- **Fix**: Address the specific error (permissions, syntax, etc.)

---

## Cleanup After Testing

### Detach Quarantine Policy (Remediation)

**Console method**:
1. Navigate to: **IAM** → **Users** → `warden-test-user`
2. Go to: **Permissions** tab
3. Find: `warden-quarantine-deny-all` policy
4. Click: **X** (Remove) → Confirm

**CLI method**:
```bash
# Get the policy ARN
POLICY_ARN=$(terraform output -raw quarantine_policy_arn)

# Detach from user
aws iam detach-user-policy \
  --user-name warden-test-user \
  --policy-arn $POLICY_ARN
```

### Delete Test Users

**Console method**:
1. Navigate to: **IAM** → **Users**
2. Select: `warden-test-user`
3. First, delete all access keys:
   - Go to **Security credentials** → Delete all keys
4. Detach all policies (if any)
5. Click: **Delete user** → Confirm

**CLI method**:
```bash
# Delete access keys first
aws iam list-access-keys --user-name warden-test-user \
  --query 'AccessKeyMetadata[].AccessKeyId' --output text | \
  xargs -I {} aws iam delete-access-key --user-name warden-test-user --access-key-id {}

# Detach policies
aws iam list-attached-user-policies --user-name warden-test-user \
  --query 'AttachedPolicies[].PolicyArn' --output text | \
  xargs -I {} aws iam detach-user-policy --user-name warden-test-user --policy-arn {}

# Delete user
aws iam delete-user --user-name warden-test-user
```

---

## Production Considerations

### False Positive Handling

If legitimate actions trigger quarantine:

1. **Immediate remediation**:
   - Detach quarantine policy from the affected user/role
   - Verify the action was legitimate
   - Document the incident

2. **Adjust EventBridge rule**:
   - Modify event pattern to exclude known-good sources
   - Add conditions to filter out legitimate use cases
   - Example: Exclude specific IAM users or roles

3. **Tune the monitoring**:
   - Review which events genuinely indicate compromise
   - Remove overly sensitive triggers
   - Add context-aware filtering (time of day, source IP, etc.)

### Recommended Next Steps

For production use, consider adding:

1. **Approval workflow**: Require human approval before quarantine
2. **Context enrichment**: Check GuardDuty, Security Hub for corroborating alerts
3. **Automated rollback**: Time-based automatic policy detachment
4. **Slack/PagerDuty integration**: Real-time alerts to security team
5. **Forensics automation**: Snapshot IAM state, collect CloudTrail logs
6. **Rate limiting**: Prevent quarantine storms during legitimate bulk operations

---

## Reference Commands

### View Recent CloudTrail Events
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --max-results 5
```

### Check Lambda Recent Invocations
```bash
aws lambda get-function --function-name warden-quarantine-lambda \
  --query 'Configuration.[LastModified,State,StateReason]'
```

### List Quarantined Users
```bash
POLICY_ARN=$(terraform output -raw quarantine_policy_arn)

# Find all users with quarantine policy attached
aws iam list-entities-for-policy --policy-arn $POLICY_ARN \
  --entity-filter User --query 'PolicyUsers[].UserName'
```

### Monitor Lambda Logs in Real-time
```bash
aws logs tail /aws/lambda/warden-quarantine-lambda --follow
```

---

## Support

If you encounter issues during testing:

1. Check CloudWatch Logs for detailed error messages
2. Verify all Terraform outputs are correct: `terraform output`
3. Ensure CloudTrail is logging management events
4. Confirm IAM permissions for Lambda execution role
5. Review the README.md for architecture details

For production deployments, thoroughly test in a non-production environment first.
