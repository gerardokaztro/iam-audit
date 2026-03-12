resource "aws_secretsmanager_secret" "slack_webhook" {
  name                    = "iam-audit/slack-webhook"
  description             = "Slack webhook URL para notificaciones de IAM Audit"
  recovery_window_in_days = 0

  tags = {
    Project     = "iam-audit"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

resource "aws_secretsmanager_secret_version" "slack_webhook" {
  secret_id     = aws_secretsmanager_secret.slack_webhook.id
  secret_string = var.slack_webhook_url
}