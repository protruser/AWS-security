locals {
  monitored_alb_dimension = trimprefix(
    split(":", aws_lb.shop.arn)[5],
    "loadbalancer/"
  )
  monitored_target_group_dimension = split(":", aws_lb_target_group.shop.arn)[5]
  monitoring_lambda_zip            = "${path.module}/lambda/build/monitoring_lambda.zip"
}

resource "terraform_data" "monitoring_lambda_package" {
  triggers_replace = [
    filesha256("${path.module}/lambda/monitoring_lambda.py"),
    filesha256("${path.module}/lambda/requirements.txt"),
    filesha256("${path.module}/lambda/build_package.py")
  ]

  provisioner "local-exec" {
    command     = "python \"${path.module}/lambda/build_package.py\""
    working_dir = path.module
  }
}

data "aws_iam_policy_document" "monitoring_lambda_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "monitoring_lambda" {
  name               = "${var.project}-monitoring-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.monitoring_lambda_assume_role.json
}

resource "aws_iam_role_policy_attachment" "monitoring_lambda_vpc" {
  role       = aws_iam_role.monitoring_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

data "aws_iam_policy_document" "monitoring_lambda" {
  statement {
    sid       = "ReadCloudWatchMetrics"
    actions   = ["cloudwatch:GetMetricData"]
    resources = ["*"]
  }

  statement {
    sid     = "ReadSecurityDatabaseSecret"
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      aws_secretsmanager_secret.security_db.arn
    ]
  }

  statement {
    sid       = "DecryptSecurityDatabaseSecret"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.security.arn]
  }
}

resource "aws_iam_role_policy" "monitoring_lambda" {
  name   = "${var.project}-monitoring-metrics"
  role   = aws_iam_role.monitoring_lambda.id
  policy = data.aws_iam_policy_document.monitoring_lambda.json
}

resource "aws_cloudwatch_log_group" "monitoring_lambda" {
  name              = "/aws/lambda/${var.project}-monitoring"
  retention_in_days = 30
}

resource "aws_lambda_function" "monitoring" {
  function_name = "${var.project}-monitoring"
  role          = aws_iam_role.monitoring_lambda.arn
  handler       = "monitoring_lambda.lambda_handler"
  runtime       = "python3.13"
  architectures = ["x86_64"]
  filename      = local.monitoring_lambda_zip
  timeout       = 60
  memory_size   = 256

  reserved_concurrent_executions = 1

  vpc_config {
    subnet_ids         = [aws_subnet.private["security_db"].id]
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      DB_SECRET_ID                     = aws_secretsmanager_secret.security_db.id
      MONITORED_INSTANCE_ID            = aws_instance.k3s.id
      MONITORED_ALB_DIMENSION          = local.monitored_alb_dimension
      MONITORED_TARGET_GROUP_DIMENSION = local.monitored_target_group_dimension
      METRIC_PERIOD_SECONDS            = tostring(var.monitoring_period_seconds)
    }
  }

  depends_on = [
    terraform_data.monitoring_lambda_package,
    aws_cloudwatch_log_group.monitoring_lambda,
    aws_iam_role_policy_attachment.monitoring_lambda_vpc,
    aws_iam_role_policy.monitoring_lambda
  ]

  lifecycle {
    replace_triggered_by = [terraform_data.monitoring_lambda_package]
  }
}

resource "aws_cloudwatch_event_rule" "monitoring" {
  name                = "${var.project}-monitoring-schedule"
  description         = "Periodically collect EC2 and ALB operational metrics"
  schedule_expression = var.monitoring_schedule_expression
}

resource "aws_cloudwatch_event_target" "monitoring" {
  rule      = aws_cloudwatch_event_rule.monitoring.name
  target_id = "MonitoringLambda"
  arn       = aws_lambda_function.monitoring.arn
}

resource "aws_lambda_permission" "allow_eventbridge_monitoring" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.monitoring.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.monitoring.arn
}
