variable "region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "notification_email" {
  description = "Email address for security alert notifications"
  type        = string
  default     = "tdemy237@gmail.com"
}
