variable "environment" {
  description = "Ambiente de despliegue"
  type        = string
}

variable "account_id" {
  description = "AWS Account ID"
  type        = string
}

variable "aws_region" {
  description = "AWS Region"
  type        = string
}

variable "reports_bucket_arn" {
  description = "ARN del bucket S3 de reportes"
  type        = string
}

variable "audit_role_name" {
  description = "Nombre del rol a asumir en cuentas miembro"
  type        = string
  default     = "AWSControlTowerExecution"
}

variable "management_account_id" {
  description = "Account ID de la cuenta Management de AWS Organizations"
  type        = string
}