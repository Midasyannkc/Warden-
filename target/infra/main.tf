terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "member_documents" {
  bucket = "careloop-member-documents"
  acl    = "public-read"
}

resource "aws_s3_bucket" "audit_logs" {
  bucket = "careloop-audit-logs"
}

resource "aws_iam_policy" "app_policy" {
  name = "careloop-app"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role" "app" {
  name = "careloop-app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "*" }
    }]
  })
}

resource "aws_security_group" "api" {
  name   = "careloop-api"
  vpc_id = "vpc-0123456789abcdef0"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
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

resource "aws_db_instance" "members" {
  identifier          = "careloop-members"
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  allocated_storage   = 50
  username            = "careloop"
  password            = "changeme-careloop-2024"
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
}

resource "aws_eks_cluster" "platform" {
  name     = "careloop-platform"
  role_arn = aws_iam_role.app.arn
  vpc_config {
    subnet_ids              = ["subnet-0123456789abcdef0", "subnet-0fedcba9876543210"]
    endpoint_public_access  = true
    endpoint_private_access = false
  }
}
