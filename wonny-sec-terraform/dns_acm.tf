resource "aws_acm_certificate" "shop" {
  count = var.enable_custom_domain ? 1 : 0

  domain_name       = var.shop_domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_acm_certificate" "admin" {
  count = var.enable_custom_domain ? 1 : 0

  domain_name       = var.admin_domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "shop_validation" {
  for_each = var.enable_custom_domain ? {
    for dvo in aws_acm_certificate.shop[0].domain_validation_options :
    dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  allow_overwrite = true
  zone_id         = var.route53_zone_id
  name            = each.value.name
  type            = each.value.type
  ttl             = 60
  records         = [each.value.record]
}

resource "aws_route53_record" "admin_validation" {
  for_each = var.enable_custom_domain ? {
    for dvo in aws_acm_certificate.admin[0].domain_validation_options :
    dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  allow_overwrite = true
  zone_id         = var.route53_zone_id
  name            = each.value.name
  type            = each.value.type
  ttl             = 60
  records         = [each.value.record]
}

resource "aws_acm_certificate_validation" "shop" {
  count = var.enable_custom_domain ? 1 : 0

  certificate_arn         = aws_acm_certificate.shop[0].arn
  validation_record_fqdns = [for r in aws_route53_record.shop_validation : r.fqdn]
}

resource "aws_acm_certificate_validation" "admin" {
  count = var.enable_custom_domain ? 1 : 0

  certificate_arn         = aws_acm_certificate.admin[0].arn
  validation_record_fqdns = [for r in aws_route53_record.admin_validation : r.fqdn]
}

resource "aws_lb_listener" "shop_https" {
  count = var.enable_custom_domain ? 1 : 0

  load_balancer_arn = aws_lb.shop.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.shop[0].certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.shop.arn
  }
}

resource "aws_lb_listener" "admin_https" {
  count = var.enable_custom_domain ? 1 : 0

  load_balancer_arn = aws_lb.admin.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.admin[0].certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.admin.arn
  }
}

resource "aws_route53_record" "shop" {
  count = var.enable_custom_domain ? 1 : 0

  zone_id = var.route53_zone_id
  name    = var.shop_domain
  type    = "A"

  alias {
    name                   = aws_lb.shop.dns_name
    zone_id                = aws_lb.shop.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "admin" {
  count = var.enable_custom_domain ? 1 : 0

  zone_id = var.route53_zone_id
  name    = var.admin_domain
  type    = "A"

  alias {
    name                   = aws_lb.admin.dns_name
    zone_id                = aws_lb.admin.zone_id
    evaluate_target_health = true
  }
}
