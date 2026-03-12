terraform {
  required_version = ">= 1.14.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {}
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}

data "aws_caller_identity" "current" {}

module "s3" {
  source = "./modules/s3"

  account_id  = data.aws_caller_identity.current.account_id
  environment = var.environment
}

module "iam" {
  source = "./modules/iam"

  account_id = data.aws_caller_identity.current.account_id
  environment = var.environment
  aws_region = var.aws_region
  reports_bucket_arn = module.s3.bucket_arn
  management_account_id = var.management_account_id
}

module "secrets" {
  source = "./modules/secrets"

  environment       = var.environment
  slack_webhook_url = var.slack_webhook_url
}

module "ecs" {
  source = "./modules/ecs"

  aws_region = var.aws_region
  environment = var.environment
  management_account_id = var.management_account_id
  task_execution_role_arn = module.iam.task_execution_role_arn
  task_role_arn = module.iam.task_role_arn
  reports_bucket_name = module.s3.bucket_name
  slack_webhook_secret_arn = module.secrets.slack_webhook_secret_arn
  audit_role_name          = var.audit_role_name
}

module "eventbridge" {
  source = "./modules/eventbridge"

  environment = var.environment
  task_execution_role_arn = module.iam.task_execution_role_arn
  task_role_arn = module.iam.task_role_arn
  task_definition_arn = module.ecs.task_definition_arn
  cluster_arn = module.ecs.cluster_arn
  
}