resource "aws_instance" "k3s" {
  ami                    = data.aws_ssm_parameter.al2023_ami.value
  instance_type          = var.instance_types.k3s
  subnet_id              = aws_subnet.private["service"].id
  vpc_security_group_ids = [aws_security_group.k3s.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2["k3s"].name

  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.shop.arn
    volume_type = "gp3"
    volume_size = 20
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = {
    Name = "${var.project}-01-k3s-nginx"
    Role = "k3s-nginx"
  }
}

resource "aws_instance" "dashboard" {
  ami                    = data.aws_ssm_parameter.al2023_ami.value
  instance_type          = var.instance_types.dashboard
  subnet_id              = aws_subnet.private["dashboard"].id
  vpc_security_group_ids = [aws_security_group.dashboard.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2["dashboard"].name

  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.security.arn
    volume_type = "gp3"
    volume_size = 20
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = {
    Name = "${var.project}-02-dashboard"
    Role = "dashboard"
  }
}

resource "aws_instance" "shop_app" {
  ami                    = data.aws_ssm_parameter.al2023_ami.value
  instance_type          = var.instance_types.shop_app
  subnet_id              = aws_subnet.private["shop_db"].id
  vpc_security_group_ids = [aws_security_group.shop_app.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2["shop-app"].name

  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.shop.arn
    volume_type = "gp3"
    volume_size = 20
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = {
    Name = "${var.project}-03-shop-app"
    Role = "shop-app"
  }
}

resource "aws_instance" "shop_db" {
  ami                    = data.aws_ssm_parameter.al2023_ami.value
  instance_type          = var.instance_types.shop_db
  subnet_id              = aws_subnet.private["shop_db"].id
  vpc_security_group_ids = [aws_security_group.shop_db.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2["shop-db"].name

  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.shop.arn
    volume_type = "gp3"
    volume_size = 30
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = {
    Name = "${var.project}-03-shop-mysql"
    Role = "shop-db"
  }
}

resource "aws_instance" "security_db" {
  ami                    = data.aws_ssm_parameter.al2023_ami.value
  instance_type          = var.instance_types.security_db
  subnet_id              = aws_subnet.private["security_db"].id
  vpc_security_group_ids = [aws_security_group.security_db.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2["security-db"].name

  root_block_device {
    encrypted   = true
    kms_key_id  = aws_kms_key.security.arn
    volume_type = "gp3"
    volume_size = 30
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = {
    Name = "${var.project}-04-security-mysql"
    Role = "security-db"
  }
}
