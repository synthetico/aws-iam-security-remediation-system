terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = "warden-security"
      ManagedBy = "terraform"
      Purpose   = "iam-security-remediation"
    }
  }
}
