import json
import boto3
import os
import logging
from datetime import datetime
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
iam_client = boto3.client('iam')
sns_client = boto3.client('sns')

# Environment variables
QUARANTINE_POLICY_ARN = os.environ['QUARANTINE_POLICY_ARN']
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']


def lambda_handler(event, context):
    """
    Main Lambda handler for processing CloudTrail security events.
    Quarantines IAM principals by attaching a deny-all policy and notifies via SNS.
    """
    logger.info(f"Received event: {json.dumps(event)}")

    try:
        # Extract CloudTrail event details
        detail = event.get('detail', {})
        event_name = detail.get('eventName', 'Unknown')
        event_time = detail.get('eventTime', 'Unknown')
        event_source = detail.get('eventSource', 'Unknown')
        aws_region = detail.get('awsRegion', 'Unknown')
        source_ip = detail.get('sourceIPAddress', 'Unknown')
        user_agent = detail.get('userAgent', 'Unknown')

        # Extract user identity information
        user_identity = detail.get('userIdentity', {})
        principal_type = user_identity.get('type', 'Unknown')
        principal_arn = user_identity.get('arn', 'Unknown')
        principal_id = user_identity.get('principalId', 'Unknown')
        account_id = user_identity.get('accountId', 'Unknown')

        # Parse principal name and type for quarantine action
        if event_name in ["CreateAccessKey", "AttachUserPolicy"]:
            principal_name = detail.get('requestParameters', {}).get('userName')
            identity_type = 'user'
            if not principal_name:
                logger.error("Unable to extract target user from requestParameters")
                return {
                    'statusCode': 400,
                    'body': json.dumps('Unable to extract target user')
                }
        else:
            principal_name, identity_type = parse_principal_identity(user_identity)

        if not principal_name or not identity_type:
            logger.error("Unable to extract principal information from event")
            return {
                'statusCode': 400,
                'body': json.dumps('Unable to extract principal information')
            }

        logger.info(f"Processing suspicious event '{event_name}' by {identity_type} '{principal_name}'")

        # Quarantine the principal by attaching deny-all policy
        quarantine_result = quarantine_principal(principal_name, identity_type)

        # Prepare notification message
        notification_message = format_notification_message(
            event_name=event_name,
            event_time=event_time,
            event_source=event_source,
            aws_region=aws_region,
            source_ip=source_ip,
            user_agent=user_agent,
            principal_type=principal_type,
            principal_name=principal_name,
            principal_arn=principal_arn,
            principal_id=principal_id,
            account_id=account_id,
            identity_type=identity_type,
            quarantine_result=quarantine_result
        )

        # Send SNS notification
        send_notification(notification_message, event_name)

        logger.info(f"Successfully processed event and quarantined {identity_type} '{principal_name}'")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Quarantine action completed successfully',
                'principal': principal_name,
                'type': identity_type,
                'event': event_name
            })
        }

    except Exception as e:
        logger.error(f"Error processing event: {str(e)}", exc_info=True)
        # Send error notification
        try:
            error_message = f"WARDEN ERROR: Failed to process security event\n\nError: {str(e)}\n\nEvent: {json.dumps(event, indent=2)}"
            send_notification(error_message, "ERROR")
        except Exception as notification_error:
            logger.error(f"Failed to send error notification: {str(notification_error)}")

        return {
            'statusCode': 500,
            'body': json.dumps(f'Error processing event: {str(e)}')
        }


def parse_principal_identity(user_identity):
    """
    Parse user identity from CloudTrail event to extract principal name and type.
    Returns: (principal_name, identity_type) tuple
    """
    principal_type = user_identity.get('type', '')
    arn = user_identity.get('arn', '')

    # Handle IAM User
    if principal_type == 'IAMUser':
        # ARN format: arn:aws:iam::123456789012:user/username
        if '/user/' in arn:
            principal_name = arn.split('/user/')[-1]
            return principal_name, 'user'
        else:
            # Fallback to userName field
            principal_name = user_identity.get('userName', '')
            return principal_name, 'user'

    # Handle Assumed Role
    elif principal_type == 'AssumedRole':
        # ARN format: arn:aws:sts::123456789012:assumed-role/role-name/session-name
        # We need to extract the role name
        session_context = user_identity.get('sessionContext', {})
        session_issuer = session_context.get('sessionIssuer', {})

        # Get the role ARN from sessionIssuer
        role_arn = session_issuer.get('arn', '')
        if '/role/' in role_arn:
            principal_name = role_arn.split('/role/')[-1]
            return principal_name, 'role'

        # Fallback: parse from principalId (format: AIDAI....:role-name)
        principal_id = user_identity.get('principalId', '')
        if ':' in principal_id:
            principal_name = principal_id.split(':')[-1]
            return principal_name, 'role'

    # Handle Root account
    elif principal_type == 'Root':
        logger.warning("Root account detected - skipping quarantine for safety")
        return None, None

    logger.warning(f"Unknown principal type: {principal_type}")
    return None, None


def quarantine_principal(principal_name, identity_type):
    """
    Attach the quarantine deny-all policy to the specified IAM principal.
    Handles idempotency - safely processes if policy is already attached.
    """
    try:
        if identity_type == 'user':
            # Attach policy to IAM user
            iam_client.attach_user_policy(
                UserName=principal_name,
                PolicyArn=QUARANTINE_POLICY_ARN
            )
            logger.info(f"Successfully attached quarantine policy to user '{principal_name}'")
            return f"Successfully quarantined IAM user '{principal_name}'"

        elif identity_type == 'role':
            # Attach policy to IAM role
            iam_client.attach_role_policy(
                RoleName=principal_name,
                PolicyArn=QUARANTINE_POLICY_ARN
            )
            logger.info(f"Successfully attached quarantine policy to role '{principal_name}'")
            return f"Successfully quarantined IAM role '{principal_name}'"

        else:
            logger.error(f"Unknown identity type: {identity_type}")
            return f"ERROR: Unknown identity type '{identity_type}'"

    except ClientError as e:
        error_code = e.response['Error']['Code']

        # Handle idempotency - policy already attached
        if error_code == 'EntityAlreadyExists' or 'already attached' in str(e):
            logger.info(f"Quarantine policy already attached to {identity_type} '{principal_name}' - idempotent operation")
            return f"Quarantine policy already attached to {identity_type} '{principal_name}' (idempotent)"

        # Handle non-existent principal
        elif error_code == 'NoSuchEntity':
            logger.warning(f"{identity_type.capitalize()} '{principal_name}' does not exist - may have been deleted")
            return f"WARNING: {identity_type.capitalize()} '{principal_name}' not found - may have been deleted"

        # Other errors
        else:
            logger.error(f"Failed to attach policy to {identity_type} '{principal_name}': {str(e)}")
            raise


def format_notification_message(event_name, event_time, event_source, aws_region,
                                source_ip, user_agent, principal_type, principal_name,
                                principal_arn, principal_id, account_id, identity_type,
                                quarantine_result):
    """
    Format a detailed notification message for SNS alerts.
    """
    message = f"""
WARDEN SECURITY ALERT: Suspicious Activity Detected and Quarantined

=== EVENT DETAILS ===
Event Name: {event_name}
Event Time: {event_time}
Event Source: {event_source}
AWS Region: {aws_region}
Source IP: {source_ip}
User Agent: {user_agent}

=== PRINCIPAL INFORMATION ===
Type: {principal_type}
Name: {principal_name}
ARN: {principal_arn}
Principal ID: {principal_id}
Account ID: {account_id}

=== QUARANTINE ACTION ===
Action Taken: Attached deny-all quarantine policy
Identity Type: {identity_type}
Result: {quarantine_result}
Policy ARN: {QUARANTINE_POLICY_ARN}

=== RECOMMENDED ACTIONS ===
1. Review CloudTrail logs for additional suspicious activity
2. Investigate the source IP address and user agent
3. Verify if this was legitimate activity
4. If legitimate, detach the quarantine policy: aws iam detach-{identity_type}-policy --{identity_type}-name {principal_name} --policy-arn {QUARANTINE_POLICY_ARN}
5. If compromised, rotate credentials and review all actions taken by this principal

=== TIMESTAMP ===
Alert Generated: {datetime.utcnow().isoformat()}Z

This is an automated alert from the Warden IAM Security Remediation System.
"""
    return message.strip()


def send_notification(message, event_name):
    """
    Publish notification message to SNS topic.
    """
    try:
        response = sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"WARDEN ALERT: {event_name} - IAM Principal Quarantined",
            Message=message
        )
        logger.info(f"SNS notification sent successfully. MessageId: {response['MessageId']}")
    except ClientError as e:
        logger.error(f"Failed to send SNS notification: {str(e)}")
        raise
