output "bucket_name" {
  description = "Nombre del bucket de reportes"
  value       = aws_s3_bucket.reports.bucket
}

output "bucket_arn" {
  description = "ARN del bucket de reportes"
  value       = aws_s3_bucket.reports.arn
}