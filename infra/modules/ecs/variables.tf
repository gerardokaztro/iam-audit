variable "aws_region" {
  description = "AWS region donde se despliega la infraestructura"
  type        = string
}

variable "environment" {
  description = "Ambiente de despliegue"
  type        = string
  default     = "sandbox"
}

variable "task_execution_role_arn" {
  description = "ARN del ECS Task Execution Role"
  type        = string
}

variable "task_role_arn" {
  description = "ARN del ECS Task Role"
  type        = string
}

variable "reports_bucket_name" {
  description = "Nombre del bucket S3 donde se suben los reportes"
  type        = string
}

variable "slack_webhook_secret_arn" {
  description = "ARN del secreto en Secrets Manager con el webhook de Slack"
  type        = string
}

variable "audit_role_name" {
  description = "Nombre del rol IAM a asumir en cuentas miembro"
  type        = string
  default     = "AWSControlTowerExecution"
}

variable "management_account_id" {
  description = "Account ID de la cuenta Management de AWS Organizations"
  type        = string
}