output "quarantine_policy_arn" {
  description = "ARN of the quarantine deny-all policy"
  value       = aws_iam_policy.warden_quarantine_deny_all.arn
}

output "sns_topic_arn" {
  description = "ARN of the security alerts SNS topic"
  value       = aws_sns_topic.warden_security_alerts.arn
}

output "lambda_function_arn" {
  description = "ARN of the quarantine Lambda function"
  value       = aws_lambda_function.warden_quarantine.arn
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge CloudTrail monitoring rule"
  value       = aws_cloudwatch_event_rule.warden_cloudtrail_monitor.arn
}

output "dlq_url" {
  description = "URL of the Lambda dead letter queue"
  value       = aws_sqs_queue.warden_dlq.url
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group for Lambda function"
  value       = aws_cloudwatch_log_group.warden_lambda_logs.name
}
