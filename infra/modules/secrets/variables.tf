variable "environment" {
  description = "Ambiente de despliegue"
  type        = string
}

variable "slack_webhook_url" {
  description = "Slack webhook URL para notificaciones"
  type        = string
  sensitive   = true
}