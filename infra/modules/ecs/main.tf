resource "aws_ecs_cluster" "main" {
  name = "iam-audit-cluster"

  tags = {
    Project     = "iam-audit"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_cloudwatch_log_group" "iam_audit" {
  name              = "/ecs/iam-audit"
  retention_in_days = 30

  tags = {
    Project     = "iam-audit"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_ecs_task_definition" "iam_audit" {
  family                   = "iam-audit"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = var.task_execution_role_arn
  task_role_arn            = var.task_role_arn

  container_definitions = jsonencode([{
    name      = "iam-audit"
    image     = "gerardokaztro/iam-audit:latest"
    essential = true

    environment = [
      {
        name  = "AWS_DEFAULT_REGION"
        value = var.aws_region
      },
      {
        name  = "MANAGEMENT_ACCOUNT_ID"
        value = var.management_account_id
      },
      {
        name  = "AUDIT_ROLE_NAME"
        value = var.audit_role_name
      },
      {
        name  = "S3_BUCKET"
        value = var.reports_bucket_name
      }
    ]

    secrets = [
      {
        name      = "SLACK_WEBHOOK_URL"
        valueFrom = var.slack_webhook_secret_arn
      }
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "/ecs/iam-audit"
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])

  tags = {
    Project     = "iam-audit"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}