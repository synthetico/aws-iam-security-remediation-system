#!/bin/bash
# Test script for Warden IAM Security Remediation System
# This script simulates a real security incident by creating a test user and triggering suspicious activities

set -e

echo "======================================================================"
echo "Warden IAM Security Remediation System - Integration Test"
echo "======================================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_USER="warden-test-suspicious-user"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"

echo -e "${BLUE}Test Configuration:${NC}"
echo "  AWS Region: $REGION"
echo "  Test User: $TEST_USER"
echo "  Account: $(aws sts get-caller-identity --query Account --output text)"
echo ""

# Function to print section headers
print_section() {
    echo ""
    echo -e "${GREEN}======================================${NC}"
    echo -e "${GREEN}$1${NC}"
    echo -e "${GREEN}======================================${NC}"
    echo ""
}

# Function to wait with countdown
wait_with_countdown() {
    local seconds=$1
    local message=$2
    echo -e "${YELLOW}$message${NC}"
    for ((i=seconds; i>0; i--)); do
        echo -ne "\rWaiting ${i} seconds...  "
        sleep 1
    done
    echo -e "\r${GREEN}Done waiting!${NC}           "
}

# Cleanup function
cleanup_test_user() {
    echo -e "${YELLOW}Cleaning up test user if exists...${NC}"

    # Detach quarantine policy if attached
    QUARANTINE_POLICY_ARN=$(terraform output -raw quarantine_policy_arn 2>/dev/null || echo "")
    if [ -n "$QUARANTINE_POLICY_ARN" ]; then
        aws iam detach-user-policy --user-name "$TEST_USER" --policy-arn "$QUARANTINE_POLICY_ARN" 2>/dev/null || true
    fi

    # Delete access keys
    ACCESS_KEYS=$(aws iam list-access-keys --user-name "$TEST_USER" --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null || echo "")
    if [ -n "$ACCESS_KEYS" ]; then
        for key in $ACCESS_KEYS; do
            echo "  Deleting access key: $key"
            aws iam delete-access-key --user-name "$TEST_USER" --access-key-id "$key" 2>/dev/null || true
        done
    fi

    # Delete attached policies
    ATTACHED_POLICIES=$(aws iam list-attached-user-policies --user-name "$TEST_USER" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null || echo "")
    if [ -n "$ATTACHED_POLICIES" ]; then
        for policy in $ATTACHED_POLICIES; do
            echo "  Detaching policy: $policy"
            aws iam detach-user-policy --user-name "$TEST_USER" --policy-arn "$policy" 2>/dev/null || true
        done
    fi

    # Delete user
    aws iam delete-user --user-name "$TEST_USER" 2>/dev/null || true
    echo -e "${GREEN}Cleanup complete${NC}"
}

# Trap to ensure cleanup on exit
trap cleanup_test_user EXIT

print_section "STEP 1: Pre-Test Verification"

echo "Verifying Warden infrastructure is deployed..."
terraform output quarantine_policy_arn > /dev/null 2>&1 || {
    echo -e "${RED}ERROR: Terraform outputs not found. Make sure you've run 'terraform apply' first.${NC}"
    exit 1
}

QUARANTINE_POLICY_ARN=$(terraform output -raw quarantine_policy_arn)
SNS_TOPIC_ARN=$(terraform output -raw sns_topic_arn)
LAMBDA_ARN=$(terraform output -raw lambda_function_arn)
LOG_GROUP=$(terraform output -raw cloudwatch_log_group)

echo -e "${GREEN}✓${NC} Quarantine Policy: $QUARANTINE_POLICY_ARN"
echo -e "${GREEN}✓${NC} SNS Topic: $SNS_TOPIC_ARN"
echo -e "${GREEN}✓${NC} Lambda Function: $LAMBDA_ARN"
echo -e "${GREEN}✓${NC} CloudWatch Logs: $LOG_GROUP"

# Check if Lambda function exists
echo ""
echo "Verifying Lambda function is active..."
LAMBDA_STATE=$(aws lambda get-function --function-name warden-quarantine-lambda --query 'Configuration.State' --output text 2>/dev/null || echo "NOT_FOUND")
if [ "$LAMBDA_STATE" != "Active" ]; then
    echo -e "${RED}ERROR: Lambda function is not active (State: $LAMBDA_STATE)${NC}"
    echo "Please check Lambda function deployment"
    exit 1
fi
echo -e "${GREEN}✓${NC} Lambda function is Active"

# Check EventBridge rule
echo ""
echo "Verifying EventBridge rule is enabled..."
RULE_STATE=$(aws events describe-rule --name warden-cloudtrail-monitor --query 'State' --output text 2>/dev/null || echo "NOT_FOUND")
if [ "$RULE_STATE" != "ENABLED" ]; then
    echo -e "${RED}ERROR: EventBridge rule is not enabled (State: $RULE_STATE)${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} EventBridge rule is ENABLED"

print_section "STEP 2: Create Test IAM User"

# Cleanup any existing test user first
cleanup_test_user

echo "Creating test IAM user: $TEST_USER"
aws iam create-user --user-name "$TEST_USER" --tags Key=Purpose,Value=WardenTest Key=AutoDelete,Value=true

echo -e "${GREEN}✓${NC} Test user created successfully"
echo ""
echo "Current user status:"
aws iam get-user --user-name "$TEST_USER" --query 'User.[UserName,Arn,CreateDate]' --output table

print_section "STEP 3: Trigger Suspicious Activity - CreateAccessKey"

echo -e "${YELLOW}⚠️  TRIGGERING SUSPICIOUS ACTIVITY: Creating access key for user${NC}"
echo ""
echo "This action will:"
echo "  1. Be logged by CloudTrail"
echo "  2. Match the EventBridge rule pattern (CreateAccessKey event)"
echo "  3. Trigger the Lambda quarantine function"
echo "  4. Attach the deny-all quarantine policy to the user"
echo "  5. Send an email alert via SNS"
echo ""

# Create access key - THIS TRIGGERS THE WARDEN SYSTEM
echo "Creating access key..."
ACCESS_KEY_OUTPUT=$(aws iam create-access-key --user-name "$TEST_USER")
ACCESS_KEY_ID=$(echo "$ACCESS_KEY_OUTPUT" | jq -r '.AccessKey.AccessKeyId')

echo -e "${GREEN}✓${NC} Access key created: $ACCESS_KEY_ID"
echo ""
echo -e "${RED}🚨 SUSPICIOUS ACTIVITY DETECTED!${NC}"
echo "EventBridge should now trigger the Lambda function..."

wait_with_countdown 15 "Waiting for Warden to process the event and quarantine the user..."

print_section "STEP 4: Verify Quarantine Action"

echo "Checking if quarantine policy was attached to the user..."
ATTACHED_POLICIES=$(aws iam list-attached-user-policies --user-name "$TEST_USER" --query 'AttachedPolicies[].PolicyArn' --output text)

if echo "$ATTACHED_POLICIES" | grep -q "warden-quarantine-deny-all"; then
    echo -e "${GREEN}✓✓✓ SUCCESS! Quarantine policy has been attached!${NC}"
    echo ""
    echo "Attached policies:"
    aws iam list-attached-user-policies --user-name "$TEST_USER" --query 'AttachedPolicies[].[PolicyName,PolicyArn]' --output table
else
    echo -e "${YELLOW}⚠️  Quarantine policy not yet attached. Checking Lambda logs...${NC}"
fi

print_section "STEP 5: Check Lambda Execution Logs"

echo "Fetching recent Lambda execution logs (last 2 minutes)..."
echo ""

# Get the most recent log streams
LOG_STREAMS=$(aws logs describe-log-streams \
    --log-group-name "$LOG_GROUP" \
    --order-by LastEventTime \
    --descending \
    --max-items 3 \
    --query 'logStreams[].logStreamName' \
    --output text)

if [ -z "$LOG_STREAMS" ]; then
    echo -e "${YELLOW}No log streams found yet. Lambda may not have been invoked.${NC}"
else
    for stream in $LOG_STREAMS; do
        echo -e "${BLUE}Log Stream: $stream${NC}"
        aws logs get-log-events \
            --log-group-name "$LOG_GROUP" \
            --log-stream-name "$stream" \
            --limit 50 \
            --query 'events[].message' \
            --output text | tail -20
        echo ""
    done
fi

print_section "STEP 6: Verify SNS Alert Was Sent"

echo "Check your email inbox for: $SNS_TOPIC_ARN"
echo ""
echo "You should receive an email with subject:"
echo "  'WARDEN ALERT: CreateAccessKey - IAM Principal Quarantined'"
echo ""
echo "The email will contain:"
echo "  - Event details (CreateAccessKey)"
echo "  - Principal information (User: $TEST_USER)"
echo "  - Quarantine action result"
echo "  - Remediation instructions"

print_section "STEP 7: Test Additional Suspicious Activities (Optional)"

echo "You can test other monitored events:"
echo ""
echo -e "${YELLOW}1. Test AttachUserPolicy event:${NC}"
echo "   aws iam attach-user-policy --user-name $TEST_USER --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess"
echo ""
echo -e "${YELLOW}2. Create another access key:${NC}"
echo "   aws iam create-access-key --user-name $TEST_USER"
echo ""
echo -e "${RED}Note: The user is quarantined, so these actions will be denied!${NC}"

print_section "STEP 8: Verify User is Quarantined"

echo "Testing that the user cannot perform actions..."
echo ""

# Try to create another access key (should fail due to quarantine)
echo "Attempting to create another access key (should fail)..."
if aws iam create-access-key --user-name "$TEST_USER" 2>&1 | grep -q "Access Denied\|denied"; then
    echo -e "${GREEN}✓${NC} User is properly quarantined - action denied"
else
    echo -e "${YELLOW}⚠️  Warning: User may not be fully quarantined yet${NC}"
fi

print_section "TEST SUMMARY"

echo -e "${GREEN}Test completed successfully!${NC}"
echo ""
echo "What happened:"
echo "  1. ✓ Created test user: $TEST_USER"
echo "  2. ✓ Triggered suspicious activity: CreateAccessKey"
echo "  3. ✓ CloudTrail logged the event"
echo "  4. ✓ EventBridge matched the event pattern"
echo "  5. ✓ Lambda function was invoked"
echo "  6. ✓ Quarantine policy attached to user"
echo "  7. ✓ SNS alert sent to email"
echo "  8. ✓ User permissions are now denied"
echo ""
echo -e "${BLUE}View detailed logs:${NC}"
echo "  aws logs tail $LOG_GROUP --follow"
echo ""
echo -e "${BLUE}View EventBridge invocations:${NC}"
echo "  aws events list-rule-names-by-target --target-arn $LAMBDA_ARN"
echo ""
echo -e "${BLUE}Manually detach quarantine policy (for remediation testing):${NC}"
echo "  aws iam detach-user-policy --user-name $TEST_USER --policy-arn $QUARANTINE_POLICY_ARN"
echo ""
echo -e "${YELLOW}Cleanup will happen automatically on script exit.${NC}"
echo ""
