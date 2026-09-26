variable "region" {
  type        = string
  description = "AWS region"
  default     = "ap-northeast-2"
}

variable "project" {
  type        = string
  description = "Resource name prefix"
  default     = "wonny-sec"
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  type = list(string)
  default = [
    "10.0.10.0/24",
    "10.0.20.0/24"
  ]

  validation {
    condition     = length(var.public_subnet_cidrs) >= 2
    error_message = "ALB 사용을 위해 서로 다른 AZ의 Public Subnet이 최소 2개 필요합니다."
  }
}

variable "private_subnet_cidrs" {
  type = object({
    service     = string
    dashboard   = string
    shop_db     = string
    security_db = string
  })

  default = {
    service     = "10.0.1.0/24"
    dashboard   = "10.0.2.0/24"
    shop_db     = "10.0.3.0/24"
    security_db = "10.0.4.0/24"
  }
}

variable "admin_cidrs" {
  type        = list(string)
  description = "관리자 대시보드 접근 허용 공인 IP/CIDR"
}

variable "notification_email" {
  type        = string
  description = "Security Hub 알림을 받을 이메일. 비우면 구독을 생성하지 않음."
  default     = ""
}

variable "enable_custom_domain" {
  type        = bool
  description = "Route53 + ACM + HTTPS 사용 여부"
  default     = false
}

variable "route53_zone_id" {
  type        = string
  description = "Route53 Public Hosted Zone ID"
  default     = ""
}

variable "shop_domain" {
  type        = string
  description = "예: shop.example.com"
  default     = ""
}

variable "admin_domain" {
  type        = string
  description = "예: security.example.com"
  default     = ""
}

variable "enable_security_services" {
  type    = bool
  default = true
}

variable "enable_vpc_endpoints" {
  type        = bool
  description = "SSM/Logs/ECR/Secrets Interface Endpoint 생성. 비용 발생."
  default     = false
}

variable "force_destroy_buckets" {
  type    = bool
  default = false
}

variable "instance_types" {
  type = object({
    k3s         = string
    shop_app    = string
    dashboard   = string
    shop_db     = string
    security_db = string
  })

  default = {
    k3s         = "t3.small"
    shop_app    = "t3.small"
    dashboard   = "t3.small"
    shop_db     = "t3.small"
    security_db = "t3.small"
  }
}

variable "shop_rate_limit" {
  type        = number
  description = "WAF 5분 기준 IP별 요청 한도"
  default     = 1000
}

variable "admin_rate_limit" {
  type        = number
  description = "관리자 WAF 5분 기준 IP별 요청 한도"
  default     = 300
}

variable "github_repository" {
  type        = string
  description = "예: owner/repository"
  default     = ""
}

variable "github_oidc_provider_arn" {
  type        = string
  description = "기존 GitHub Actions OIDC Provider ARN. 없으면 비워둠."
  default     = ""
}

variable "monitoring_schedule_expression" {
  type        = string
  description = "Monitoring Lambda EventBridge 주기. 예: rate(1 minute), rate(5 minutes)"
  default     = "rate(1 minute)"

  validation {
    condition     = can(regex("^rate\\([1-9][0-9]* minutes?\\)$", var.monitoring_schedule_expression))
    error_message = "monitoring_schedule_expression은 rate(1 minute) 또는 rate(5 minutes) 형식이어야 합니다."
  }
}

variable "monitoring_period_seconds" {
  type        = number
  description = "CloudWatch 집계 구간(초). 1분 또는 5분"
  default     = 60

  validation {
    condition     = contains([60, 300], var.monitoring_period_seconds)
    error_message = "monitoring_period_seconds는 60 또는 300이어야 합니다."
  }
}
