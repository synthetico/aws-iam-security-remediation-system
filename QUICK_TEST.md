# Quick Test Guide - Warden System

## 5-Minute Console Test

### Prerequisites
- Terraform deployed: `terraform apply` ✓
- SNS email confirmed ✓
- Logged into AWS Console ✓

---

## Test Steps

### 1. CREATE TEST USER (2 minutes)

**AWS Console** → **IAM** → **Users** → **Add users**

```
Username: warden-test-user
Permissions: None
Tags: Purpose=WardenTest
```

Click **Create user**

---

### 2. TRIGGER SUSPICIOUS ACTIVITY (30 seconds)

Still in IAM → Click **warden-test-user**

Go to: **Security credentials** tab

Click: **Create access key**

```
Use case: Command Line Interface (CLI)
Check: I understand
Description: Test key
```

Click: **Create access key**

🚨 **WARDEN TRIGGERED!**

---

### 3. WATCH IT HAPPEN (30 seconds)

**Open new tab** → **CloudWatch** → **Logs** → **Log groups**

Find: `/aws/lambda/warden-quarantine-lambda`

Click → Select newest **Log stream**

**Enable auto-refresh** (toggle top-right)

You'll see:
```
INFO Processing suspicious event 'CreateAccessKey' by user 'warden-test-user'
INFO Successfully attached quarantine policy to user 'warden-test-user'
INFO SNS notification sent successfully
```

---

### 4. VERIFY QUARANTINE (30 seconds)

**Go back to IAM tab** → **warden-test-user** → **Permissions**

**Look for**: `warden-quarantine-deny-all` policy attached ✓

---

### 5. CHECK EMAIL (1 minute)

**Check your inbox**

Subject: `WARDEN ALERT: CreateAccessKey - IAM Principal Quarantined`

Contains:
- Event details
- User information
- Quarantine confirmation
- Remediation steps

---

### 6. TEST IT'S BLOCKED (30 seconds)

Still in IAM → **warden-test-user** → **Security credentials**

Try: **Create access key** again

**Result**: Action denied or fails ✓

---

## Alternative: Automated Test

Instead of manual console steps, run:

```bash
./test-warden.sh
```

This automates everything and provides detailed output.

---

## Expected Timeline

| Time | Event |
|------|-------|
| T+0s | Create access key (suspicious activity) |
| T+5s | CloudTrail logs event |
| T+10s | EventBridge matches pattern |
| T+10s | Lambda invoked |
| T+15s | Quarantine policy attached |
| T+20s | SNS email sent |
| T+1min | Email arrives in inbox |

---

## Success Indicators

✓ CloudWatch logs show "Successfully attached quarantine policy"
✓ IAM user has `warden-quarantine-deny-all` policy
✓ Email alert received with full details
✓ Subsequent user actions are denied

---

## Cleanup

**Detach quarantine policy**:
```bash
aws iam detach-user-policy \
  --user-name warden-test-user \
  --policy-arn $(terraform output -raw quarantine_policy_arn)
```

**Delete test user**:
```bash
# Delete access keys first
aws iam list-access-keys --user-name warden-test-user \
  --query 'AccessKeyMetadata[].AccessKeyId' --output text | \
  xargs -I {} aws iam delete-access-key --user-name warden-test-user --access-key-id {}

# Delete user
aws iam delete-user --user-name warden-test-user
```

Or use the automated test script which cleans up automatically.

---

## Troubleshooting

**No logs appearing?**
- Check CloudTrail is enabled
- Verify EventBridge rule is enabled
- Wait 30 seconds (events may be delayed)

**Policy not attached?**
- Check Lambda execution logs for errors
- Verify Lambda has IAM permissions
- Ensure user wasn't root account (root is excluded)

**No email?**
- Confirm SNS subscription (check spam folder)
- Check SNS console for delivery failures
- Verify email address is correct

---

## Test Other Events

**AttachUserPolicy** (privilege escalation):
```
IAM → Users → Create new user → Add permissions → Attach policy
```

**DeleteBucket** (data destruction):
```
S3 → Create test bucket → Delete bucket
⚠️  This will quarantine YOUR user, use test account!
```

---

## Production Notes

This is a **prototype for learning**. Before production:

- Add approval workflows
- Tune event patterns to reduce false positives
- Integrate with GuardDuty/Security Hub
- Add automated forensics collection
- Set up team alerting (Slack/PagerDuty)
- Test thoroughly in non-prod environment

---

**Questions?** See full `TESTING.md` for detailed guide.
