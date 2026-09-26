locals {
  common_tags = {
    Project   = var.project
    ManagedBy = "Terraform"
  }

  public_subnets = {
    public_a = {
      cidr     = var.public_subnet_cidrs[0]
      az_index = 0
    }
    public_b = {
      cidr     = var.public_subnet_cidrs[1]
      az_index = 1
    }
  }

  private_subnets = {
    service = {
      cidr     = var.private_subnet_cidrs.service
      az_index = 0
      name     = "01-service"
    }
    dashboard = {
      cidr     = var.private_subnet_cidrs.dashboard
      az_index = 1
      name     = "02-dashboard"
    }
    shop_db = {
      cidr     = var.private_subnet_cidrs.shop_db
      az_index = 0
      name     = "03-shop-db"
    }
    security_db = {
      cidr     = var.private_subnet_cidrs.security_db
      az_index = 1
      name     = "04-security-db"
    }
  }

  instance_role_names = toset([
    "k3s",
    "shop-app",
    "dashboard",
    "shop-db",
    "security-db"
  ])
}
