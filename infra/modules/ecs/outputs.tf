output "task_definition_arn" {
  description = "ARN del Task Definition de iam-audit"
  value       = aws_ecs_task_definition.iam_audit.arn
}

output "cluster_arn" {
  description = "ARN del ECS Cluster"
  value       = aws_ecs_cluster.main.arn
}