# A single application instance in a private subnet. There is no SSH: admins
# connect with SSM Session Manager (requires a NAT gateway or SSM VPC
# endpoints, which are left out to stay in the free tier).

data "aws_partition" "current" {}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# ------------------------------------------------------------------ IAM

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  name               = "app-${var.name}-web"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.this.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "app" {
  statement {
    sid       = "ReadAssets"
    actions   = ["s3:GetObject"]
    resources = ["${var.assets_bucket_arn}/*"]
  }

  statement {
    sid       = "ListAssets"
    actions   = ["s3:ListBucket"]
    resources = [var.assets_bucket_arn]
  }
}

resource "aws_iam_role_policy" "app" {
  name   = "read-assets"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.app.json
}

resource "aws_iam_instance_profile" "this" {
  name = "app-${var.name}-web"
  role = aws_iam_role.this.name
}

# ------------------------------------------------------------- networking

resource "aws_security_group" "this" {
  name        = "${var.name}-web"
  description = "Application instances"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.name}-web"
  }
}

resource "aws_vpc_security_group_ingress_rule" "https_from_vpc" {
  security_group_id = aws_security_group.this.id
  description       = "HTTPS from inside the VPC (for example a load balancer)"
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "https" {
  security_group_id = aws_security_group.this.id
  description       = "HTTPS to AWS APIs and package repositories"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "postgres" {
  security_group_id = aws_security_group.this.id
  description       = "PostgreSQL inside the VPC"
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "tcp"
  from_port         = 5432
  to_port           = 5432
}

# --------------------------------------------------------------- instance

resource "aws_instance" "this" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [aws_security_group.this.id]
  iam_instance_profile        = aws_iam_instance_profile.this.name
  associate_public_ip_address = false
  monitoring                  = true
  ebs_optimized               = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    encrypted             = true
    volume_type           = "gp3"
    delete_on_termination = true
  }

  tags = {
    Name = "${var.name}-web"
  }

  lifecycle {
    # A newer AMI must not replace the instance on every plan (and trip the
    # nightly drift check). Roll AMIs deliberately instead.
    ignore_changes = [ami]
  }
}
