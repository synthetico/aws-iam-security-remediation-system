# KMS key for SNS topic encryption
resource "aws_kms_key" "warden_sns" {
  description             = "KMS key for Warden security alerts SNS topic encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = {
    Name = "warden-sns-encryption-key"
  }
}

resource "aws_kms_alias" "warden_sns" {
  name          = "alias/warden-sns-encryption"
  target_key_id = aws_kms_key.warden_sns.key_id
}

# SNS topic for security alerts
resource "aws_sns_topic" "warden_security_alerts" {
  name              = "warden-security-alerts"
  display_name      = "Warden Security Alerts"
  kms_master_key_id = aws_kms_key.warden_sns.id

  tags = {
    Name = "warden-security-alerts"
  }
}

# SNS topic policy to allow EventBridge and Lambda to publish
resource "aws_sns_topic_policy" "warden_security_alerts" {
  arn = aws_sns_topic.warden_security_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLambdaPublish"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.warden_security_alerts.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# Email subscription to SNS topic
resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.warden_security_alerts.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# S3 bucket for CloudTrail logs
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "warden-trail-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_policy" "cloudtrail_logs_policy" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "warden_trail" {
  name           = "warden-trail"
  s3_bucket_name = aws_s3_bucket.cloudtrail_logs.bucket
}

# IAM Quarantine Policy - Deny all actions
resource "aws_iam_policy" "warden_quarantine_deny_all" {
  name        = "warden-quarantine-deny-all"
  description = "Quarantine policy that denies all AWS actions - applied to compromised principals"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyAllActions"
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
      },
      # Explicitly deny critical IAM privilege escalation actions
      {
        Sid    = "DenyIAMPrivilegeEscalation"
        Effect = "Deny"
        Action = [
          "iam:AttachUserPolicy",
          "iam:AttachRolePolicy",
          "iam:CreateAccessKey",
          "iam:CreateLoginProfile",
          "iam:CreateUser",
          "iam:DeleteUserPolicy",
          "iam:DeleteRolePolicy",
          "iam:PutUserPolicy",
          "iam:PutRolePolicy",
          "iam:AddUserToGroup",
          "iam:UpdateAssumeRolePolicy"
        ]
        Resource = "*"
      },
      # Deny compute resource creation
      {
        Sid    = "DenyComputeActions"
        Effect = "Deny"
        Action = [
          "ec2:RunInstances",
          "lambda:CreateFunction",
          "lambda:UpdateFunctionCode",
          "ecs:RunTask",
          "batch:SubmitJob"
        ]
        Resource = "*"
      },
      # Deny data exfiltration vectors
      {
        Sid    = "DenyDataExfiltration"
        Effect = "Deny"
        Action = [
          "s3:PutBucketPolicy",
          "s3:PutBucketAcl",
          "s3:PutObjectAcl",
          "rds:ModifyDBInstance",
          "rds:CreateDBSnapshot"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "warden-quarantine-deny-all"
  }
}

# Dead Letter Queue for failed Lambda invocations
resource "aws_sqs_queue" "warden_dlq" {
  name                      = "warden-lambda-dlq"
  message_retention_seconds = 1209600 # 14 days

  tags = {
    Name = "warden-lambda-dlq"
  }
}

# IAM role for Lambda execution
resource "aws_iam_role" "warden_lambda_execution" {
  name = "warden-lambda-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "warden-lambda-execution-role"
  }
}

# IAM policy for Lambda - least privilege permissions
resource "aws_iam_role_policy" "warden_lambda_permissions" {
  name = "warden-lambda-permissions"
  role = aws_iam_role.warden_lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # CloudWatch Logs permissions
      {
        Sid    = "CloudWatchLogsAccess"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/warden-quarantine-lambda:*"
      },
      # IAM permissions to attach quarantine policy
      {
        Sid    = "AttachQuarantinePolicy"
        Effect = "Allow"
        Action = [
          "iam:AttachUserPolicy",
          "iam:AttachRolePolicy"
        ]
        Resource = [
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*",
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/*"
        ]
        Condition = {
          StringEquals = {
            "iam:PolicyARN" = aws_iam_policy.warden_quarantine_deny_all.arn
          }
        }
      },
      # SNS publish permissions
      {
        Sid      = "PublishToSecurityAlerts"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.warden_security_alerts.arn
      },
      # SQS DLQ permissions
      {
        Sid    = "DLQAccess"
        Effect = "Allow"
        Action = [
          "sqs:SendMessage"
        ]
        Resource = aws_sqs_queue.warden_dlq.arn
      },
      # KMS permissions for SNS encryption
      {
        Sid    = "KMSDecryptForSNS"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.warden_sns.arn
      }
    ]
  })
}

# Lambda function for quarantine enforcement
resource "aws_lambda_function" "warden_quarantine" {
  filename      = "${path.module}/lambda_function.zip"
  function_name = "warden-quarantine-lambda"
  role          = aws_iam_role.warden_lambda_execution.arn
  handler       = "index.lambda_handler"
  runtime       = "python3.11"
  timeout       = 60
  memory_size   = 256

  dead_letter_config {
    target_arn = aws_sqs_queue.warden_dlq.arn
  }

  environment {
    variables = {
      QUARANTINE_POLICY_ARN = aws_iam_policy.warden_quarantine_deny_all.arn
      SNS_TOPIC_ARN         = aws_sns_topic.warden_security_alerts.arn
    }
  }

  tags = {
    Name = "warden-quarantine-lambda"
  }

  depends_on = [
    aws_iam_role_policy.warden_lambda_permissions
  ]
}

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "warden_lambda_logs" {
  name              = "/aws/lambda/warden-quarantine-lambda"
  retention_in_days = 30

  tags = {
    Name = "warden-lambda-logs"
  }
}

# EventBridge rule to trigger Lambda on suspicious CloudTrail events
resource "aws_cloudwatch_event_rule" "warden_cloudtrail_monitor" {
  name        = "warden-cloudtrail-monitor"
  description = "Detect suspicious CloudTrail events for automated quarantine"

  event_pattern = jsonencode({
    source      = ["aws.s3", "aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "DeleteBucket",
        "AttachUserPolicy",
        "CreateAccessKey"
      ]
    }
  })

  tags = {
    Name = "warden-cloudtrail-monitor"
  }
}

# EventBridge target - Lambda function
resource "aws_cloudwatch_event_target" "warden_lambda_target" {
  rule      = aws_cloudwatch_event_rule.warden_cloudtrail_monitor.name
  target_id = "WardenQuarantineLambda"
  arn       = aws_lambda_function.warden_quarantine.arn
}

# Lambda permission for EventBridge to invoke
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.warden_quarantine.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.warden_cloudtrail_monitor.arn
}
