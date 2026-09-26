output "vpc_id" {
  value = aws_vpc.main.id
}

output "private_subnet_ids" {
  value = {
    for k, v in aws_subnet.private : k => v.id
  }
}

output "shop_alb_dns" {
  value = aws_lb.shop.dns_name
}

output "admin_alb_dns" {
  value = aws_lb.admin.dns_name
}

output "shop_url" {
  value = var.enable_custom_domain ? "https://${var.shop_domain}" : "http://${aws_lb.shop.dns_name}"
}

output "admin_url" {
  value = var.enable_custom_domain ? "https://${var.admin_domain}" : "http://${aws_lb.admin.dns_name}"
}

output "security_log_bucket" {
  value = aws_s3_bucket.security_logs.bucket
}

output "ecr_repositories" {
  value = {
    nginx     = aws_ecr_repository.nginx.repository_url
    shop_app  = aws_ecr_repository.shop_app.repository_url
    dashboard = aws_ecr_repository.dashboard.repository_url
  }
}

output "github_deploy_role_arn" {
  value = try(aws_iam_role.github_deploy[0].arn, null)
}

output "monitoring_lambda_name" {
  value = aws_lambda_function.monitoring.function_name
}

output "monitoring_schedule" {
  value = aws_cloudwatch_event_rule.monitoring.schedule_expression
}
