# Latest security scenario mapping:
# - WAF: SQLi / XSS / directory search / brute-force login
# - GuardDuty: port scan / compromised credential scenario
# - Inspector: vulnerable EC2/ECR image
# - IAM Access Analyzer: supporting evidence for excessive/external access
# - Security Hub: aggregate supported findings
# - CloudTrail / VPC Flow Logs / CloudWatch: supporting data sources
# - Shield Standard: AWS default protection, no Terraform activation resource

resource "aws_guardduty_detector" "main" {
  count = var.enable_security_services ? 1 : 0

  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_inspector2_enabler" "main" {
  count = var.enable_security_services ? 1 : 0

  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["EC2", "ECR"]
}

resource "aws_accessanalyzer_analyzer" "main" {
  count = var.enable_security_services ? 1 : 0

  analyzer_name = "${var.project}-account-analyzer"
  type          = "ACCOUNT"
}

resource "aws_securityhub_account" "main" {
  count = var.enable_security_services ? 1 : 0

  enable_default_standards = true
}

resource "aws_sns_topic" "security_alerts" {
  name              = "${var.project}-security-alerts"
  kms_master_key_id = aws_kms_key.security.id
}

resource "aws_sns_topic_subscription" "email" {
  count = var.notification_email != "" ? 1 : 0

  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# Security Hub에 유입된 finding을 알림 경로로 전달.
# WAF 자체는 Security Hub에 직접 finding을 보내지 않으므로,
# WAF 로그 기반의 커스텀 finding 변환은 별도 Lambda/애플리케이션 로직에서 구현한다.
resource "aws_cloudwatch_event_rule" "securityhub_findings" {
  count = var.enable_security_services ? 1 : 0

  name        = "${var.project}-securityhub-findings"
  description = "Forward imported Security Hub findings to SNS"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
  })

  depends_on = [aws_securityhub_account.main]
}

resource "aws_cloudwatch_event_target" "securityhub_to_sns" {
  count = var.enable_security_services ? 1 : 0

  rule      = aws_cloudwatch_event_rule.securityhub_findings[0].name
  target_id = "SecurityAlertsSNS"
  arn       = aws_sns_topic.security_alerts.arn
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn = aws_sns_topic.security_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEventBridgePublish"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.security_alerts.arn
      }
    ]
  })
}
