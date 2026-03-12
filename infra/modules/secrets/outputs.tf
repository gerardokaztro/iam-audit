output "slack_webhook_secret_arn" {
  description = "ARN del secreto de Slack webhook"
  value       = aws_secretsmanager_secret.slack_webhook.arn
}