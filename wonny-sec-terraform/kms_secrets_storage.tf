resource "aws_kms_key" "shop" {
  description             = "${var.project} shopping data key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_kms_alias" "shop" {
  name          = "alias/${var.project}-shop"
  target_key_id = aws_kms_key.shop.key_id
}

data "aws_iam_policy_document" "security_kms" {
  # 이 계정의 IAM 정책을 통해 키 관리 권한을 위임할 수 있도록 유지
  statement {
    sid    = "EnableIAMUserPermissions"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  # WAF 로그 및 VPC Flow Logs를 저장하는 CloudWatch Log Group만 이 키 사용 허용
  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*"
    ]

    resources = ["*"]

    condition {
      test     = "ArnEquals"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values = [
        "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:aws-waf-logs-${var.project}-shop",
        "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:aws-waf-logs-${var.project}-admin",
        "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/${var.project}/vpc-flow"
      ]
    }
  }

  # 암호화된 SNS Topic으로 EventBridge가 알림을 발행할 때 필요한 권한
  statement {
    sid    = "AllowEventBridgeForEncryptedSNS"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey"
    ]

    resources = ["*"]
  }

  # S3 Bucket Key + SSE-KMS 환경에서 CloudTrail 로그 암호화 허용
  statement {
    sid    = "AllowCloudTrailEncryptLogs"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = ["kms:GenerateDataKey*"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.region}:${data.aws_caller_identity.current.account_id}:trail/${var.project}-trail"]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"]
    }
  }

  statement {
    sid    = "AllowCloudTrailDescribeAndDecrypt"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "kms:DescribeKey",
      "kms:Decrypt"
    ]

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.region}:${data.aws_caller_identity.current.account_id}:trail/${var.project}-trail"]
    }
  }
}

resource "aws_kms_key" "security" {
  description             = "${var.project} security result/log key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.security_kms.json
}

resource "aws_kms_alias" "security" {
  name          = "alias/${var.project}-security"
  target_key_id = aws_kms_key.security.key_id
}

resource "random_password" "shop_db" {
  length  = 24
  special = true
}

resource "random_password" "security_db" {
  length  = 24
  special = true
}

resource "aws_secretsmanager_secret" "shop_db" {
  name       = "${var.project}/shop-db"
  kms_key_id = aws_kms_key.shop.arn
}

resource "aws_secretsmanager_secret" "security_db" {
  name       = "${var.project}/security-db"
  kms_key_id = aws_kms_key.security.arn
}

resource "aws_secretsmanager_secret_version" "shop_db" {
  secret_id = aws_secretsmanager_secret.shop_db.id

  secret_string = jsonencode({
    username = "shop_app"
    password = random_password.shop_db.result
    port     = 3306
    database = "shop"
    host     = aws_instance.shop_db.private_ip
  })
}

resource "aws_secretsmanager_secret_version" "security_db" {
  secret_id = aws_secretsmanager_secret.security_db.id

  secret_string = jsonencode({
    username = "security_app"
    password = random_password.security_db.result
    port     = 3306
    database = "security"
    host     = aws_instance.security_db.private_ip
  })
}

resource "aws_s3_bucket" "security_logs" {
  bucket        = "${var.project}-${data.aws_caller_identity.current.account_id}-${var.region}-security-logs"
  force_destroy = var.force_destroy_buckets
}

resource "aws_s3_bucket_public_access_block" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.security.arn
    }

    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "security_logs" {
  bucket = aws_s3_bucket.security_logs.id

  rule {
    id     = "archive"
    status = "Enabled"

    filter {}

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 365
    }
  }
}
