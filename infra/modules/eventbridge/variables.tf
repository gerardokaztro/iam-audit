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

variable "task_definition_arn" {
  description = "ARN del Task Definition de iam-audit"
  type        = string
}

variable "cluster_arn" {
  description = "ARN del ECS Cluster"
  type        = string
}