resource "aws_security_group" "shop_alb" {
  name        = "${var.project}-shop-alb-sg"
  description = "Public shopping ALB"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "admin_alb" {
  name        = "${var.project}-admin-alb-sg"
  description = "Admin ALB restricted by source CIDR"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Admin HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }

  ingress {
    description = "Admin HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "k3s" {
  name        = "${var.project}-k3s-sg"
  description = "K3s nginx target"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Shopping ALB to nginx NodePort"
    from_port       = 30443
    to_port         = 30443
    protocol        = "tcp"
    security_groups = [aws_security_group.shop_alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "shop_app" {
  name        = "${var.project}-shop-app-sg"
  description = "Flask app in subnet 3"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "nginx to Flask HTTPS"
    from_port       = 8443
    to_port         = 8443
    protocol        = "tcp"
    security_groups = [aws_security_group.k3s.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "shop_db" {
  name        = "${var.project}-shop-db-sg"
  description = "Shopping MySQL"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Flask to MySQL"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.shop_app.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "dashboard" {
  name        = "${var.project}-dashboard-sg"
  description = "Dashboard Flask"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Admin ALB to Dashboard HTTPS"
    from_port       = 8443
    to_port         = 8443
    protocol        = "tcp"
    security_groups = [aws_security_group.admin_alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "lambda" {
  name        = "${var.project}-lambda-sg"
  description = "Reserved for Lambda VPC ENI"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "security_db" {
  name        = "${var.project}-security-db-sg"
  description = "Security result MySQL"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Dashboard to Security DB"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.dashboard.id]
  }

  ingress {
    description     = "Lambda to Security DB"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
