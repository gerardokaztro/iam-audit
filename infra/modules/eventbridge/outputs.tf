output "scheduler_arn" {
  description = "ARN del EventBridge Scheduler"
  value       = aws_scheduler_schedule.iam_audit.arn
}

output "security_group_id" {
  description = "ID del Security Group del ECS Task"
  value       = aws_security_group.iam_audit.id
}