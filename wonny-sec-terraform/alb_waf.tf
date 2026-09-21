resource "aws_lb" "shop" {
  name               = "${var.project}-shop-alb"
  load_balancer_type = "application"
  internal           = false
  security_groups    = [aws_security_group.shop_alb.id]
  subnets            = [for s in aws_subnet.public : s.id]

  tags = {
    Name = "${var.project}-shop-alb"
  }
}

resource "aws_lb" "admin" {
  name               = "${var.project}-admin-alb"
  load_balancer_type = "application"
  internal           = false
  security_groups    = [aws_security_group.admin_alb.id]
  subnets            = [for s in aws_subnet.public : s.id]

  tags = {
    Name = "${var.project}-admin-alb"
  }
}

resource "aws_lb_target_group" "shop" {
  name     = "${var.project}-shop-tg"
  port     = 30443
  protocol = "HTTPS"
  vpc_id   = aws_vpc.main.id

  health_check {
    enabled             = true
    protocol            = "HTTPS"
    path                = "/health"
    matcher             = "200-399"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
  }
}

resource "aws_lb_target_group" "admin" {
  name     = "${var.project}-admin-tg"
  port     = 8443
  protocol = "HTTPS"
  vpc_id   = aws_vpc.main.id

  health_check {
    enabled             = true
    protocol            = "HTTPS"
    path                = "/health"
    matcher             = "200-399"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
  }
}

resource "aws_lb_target_group_attachment" "shop" {
  target_group_arn = aws_lb_target_group.shop.arn
  target_id        = aws_instance.k3s.id
  port             = 30443
}

resource "aws_lb_target_group_attachment" "admin" {
  target_group_arn = aws_lb_target_group.admin.arn
  target_id        = aws_instance.dashboard.id
  port             = 8443
}

# 도메인이 없을 때: ALB 기본 DNS로 HTTP 접속
resource "aws_lb_listener" "shop_http_forward" {
  count = var.enable_custom_domain ? 0 : 1

  load_balancer_arn = aws_lb.shop.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.shop.arn
  }
}

resource "aws_lb_listener" "admin_http_forward" {
  count = var.enable_custom_domain ? 0 : 1

  load_balancer_arn = aws_lb.admin.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.admin.arn
  }
}

# 도메인이 있을 때: HTTP -> HTTPS
resource "aws_lb_listener" "shop_http_redirect" {
  count = var.enable_custom_domain ? 1 : 0

  load_balancer_arn = aws_lb.shop.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "admin_http_redirect" {
  count = var.enable_custom_domain ? 1 : 0

  load_balancer_arn = aws_lb.admin.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_wafv2_web_acl" "shop" {
  name  = "${var.project}-shop-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSCommonRules"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project}-shop-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSSQLiRules"
    priority = 20

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project}-shop-sqli"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "RateLimit"
    priority = 30

    action {
      block {}
    }

    statement {
      rate_based_statement {
        aggregate_key_type = "IP"
        limit              = var.shop_rate_limit
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project}-shop-rate"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project}-shop-waf"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl" "admin" {
  name  = "${var.project}-admin-waf"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSCommonRules"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project}-admin-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AdminRateLimit"
    priority = 20

    action {
      block {}
    }

    statement {
      rate_based_statement {
        aggregate_key_type = "IP"
        limit              = var.admin_rate_limit
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project}-admin-rate"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project}-admin-waf"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "shop" {
  resource_arn = aws_lb.shop.arn
  web_acl_arn  = aws_wafv2_web_acl.shop.arn
}

resource "aws_wafv2_web_acl_association" "admin" {
  resource_arn = aws_lb.admin.arn
  web_acl_arn  = aws_wafv2_web_acl.admin.arn
}

resource "aws_cloudwatch_log_group" "shop_waf" {
  name              = "aws-waf-logs-${var.project}-shop"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.security.arn
}

resource "aws_cloudwatch_log_group" "admin_waf" {
  name              = "aws-waf-logs-${var.project}-admin"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.security.arn
}

resource "aws_wafv2_web_acl_logging_configuration" "shop" {
  resource_arn            = aws_wafv2_web_acl.shop.arn
  log_destination_configs = [aws_cloudwatch_log_group.shop_waf.arn]
}

resource "aws_wafv2_web_acl_logging_configuration" "admin" {
  resource_arn            = aws_wafv2_web_acl.admin.arn
  log_destination_configs = [aws_cloudwatch_log_group.admin_waf.arn]
}
