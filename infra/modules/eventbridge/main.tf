data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "aws_security_group" "iam_audit" {
  name        = "iam-audit-task-sg"
  description = "Security group para ECS Fargate Task de iam-audit"
  vpc_id      = data.aws_vpc.default.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Project     = "iam-audit"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_iam_role" "eventbridge_role" {
  name = "iam-audit-eventbridge-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "scheduler.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Project     = "iam-audit"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_iam_role_policy" "eventbridge_role_policy" {
  name = "iam-audit-eventbridge-policy"
  role = aws_iam_role.eventbridge_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "ecs:RunTask"
        Resource = var.task_definition_arn
      },
      {
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = [
          var.task_execution_role_arn,
          var.task_role_arn
        ]
      }
    ]
  })
}

resource "aws_scheduler_schedule" "iam_audit" {
  name       = "iam-audit-weekly"
  group_name = "default"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression          = "cron(0 14 ? * MON *)"
  schedule_expression_timezone = "America/Lima"

  target {
    arn      = var.cluster_arn
    role_arn = aws_iam_role.eventbridge_role.arn

    ecs_parameters {
      task_definition_arn = var.task_definition_arn
      launch_type         = "FARGATE"

      network_configuration {
        subnets          = data.aws_subnets.default.ids
        security_groups  = [aws_security_group.iam_audit.id]
        assign_public_ip = true
      }
    }
  }
}