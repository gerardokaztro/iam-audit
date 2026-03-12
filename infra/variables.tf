variable "aws_region" {
  description = "AWS region donde se despliega la infraestructura"
  type        = string
}

variable "aws_profile" {
  description = "AWS CLI profile a usar"
  type        = string
}

variable "environment" {
  description = "Ambiente de despliegue"
  type        = string
  default     = "sandbox"
}

variable "tfstate_bucket" {
  description = "Nombre del bucket S3 para el remote state de Terraform"
  type        = string
}

variable "slack_webhook_url" {
  description = "Slack webhook URL para notificaciones"
  type        = string
  sensitive   = true
}

variable "audit_role_name" {
  description = "Nombre del rol IAM a asumir en cuentas miembro"
  type        = string
  default     = "AWSControlTowerExecution"
}

variable "reports_bucket_name" {
  description = "Nombre del bucket S3 donde se suben los reportes"
  type        = string
}

variable "management_account_id" {
  description = "Account ID de la cuenta Management de AWS Organizations"
  type        = string
}