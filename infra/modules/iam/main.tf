# Task Execution Role — lo usa ECS para arrancar el contenedor
resource "aws_iam_role" "task_execution_role" {
  name = "iam-audit-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Project     = "iam-audit"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_iam_role_policy_attachment" "task_execution_role_policy" {
  role       = aws_iam_role.task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "task_execution_secrets_policy" {
  name = "iam-audit-execution-secrets-policy"
  role = aws_iam_role.task_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "secretsmanager:GetSecretValue"
      Resource = "arn:aws:secretsmanager:${var.aws_region}:${var.account_id}:secret:iam-audit/*"
    }]
  })
}

# Task Role — lo usa el código dentro del contenedor
resource "aws_iam_role" "task_role" {
  name = "iam-audit-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Project     = "iam-audit"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_iam_role_policy" "task_role_policy" {
  name = "iam-audit-task-policy"
  role = aws_iam_role.task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AssumeRoleInMemberAccounts"
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Resource = "arn:aws:iam::*:role/${var.audit_role_name}"
      },
      {
        Sid    = "S3Reports"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${var.reports_bucket_arn}/*"
      },
      {
        Sid    = "S3PresignedUrl"
        Effect = "Allow"
        Action = "s3:GetObject"
        Resource = "${var.reports_bucket_arn}/*"
      },
      {
        Sid    = "SecretsManager"
        Effect = "Allow"
        Action = "secretsmanager:GetSecretValue"
        Resource = "arn:aws:secretsmanager:${var.aws_region}:${var.account_id}:secret:iam-audit/*"
      },
      {
        Sid    = "AssumeRoleInManagement"
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Resource = "arn:aws:iam::${var.management_account_id}:role/iam-audit-org-reader"
      }
    ]
  })
}