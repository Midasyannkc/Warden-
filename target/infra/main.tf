terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = "us-east-1"
}

locals {
  vpc_cidr = "10.0.0.0/16"
}

resource "aws_kms_key" "phi" {
  description         = "CareLoop PHI encryption"
  enable_key_rotation = true
}

# ---------- S3 ----------
resource "aws_s3_bucket" "audit_logs" {
  bucket = "careloop-audit-logs"
}

resource "aws_s3_bucket" "member_documents" {
  bucket = "careloop-member-documents"
}

resource "aws_s3_bucket_public_access_block" "member_documents" {
  bucket                  = aws_s3_bucket.member_documents.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket                  = aws_s3_bucket.audit_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "member_documents" {
  bucket = aws_s3_bucket.member_documents.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
  }
}

resource "aws_s3_bucket_versioning" "member_documents" {
  bucket = aws_s3_bucket.member_documents.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "member_documents" {
  bucket        = aws_s3_bucket.member_documents.id
  target_bucket = aws_s3_bucket.audit_logs.id
  target_prefix = "s3-access/"
}

resource "aws_s3_bucket_lifecycle_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  rule {
    id     = "retain-six-years"
    status = "Enabled"
    filter {}
    expiration {
      days = 2190
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# ---------- IAM ----------
resource "aws_iam_policy" "app_policy" {
  name = "careloop-app"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "${aws_s3_bucket.member_documents.arn}/*"
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
      Principal = { Service = "eks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "app" {
  role       = aws_iam_role.app.name
  policy_arn = aws_iam_policy.app_policy.arn
}

resource "aws_iam_role" "rds_monitoring" {
  name = "careloop-rds-monitoring"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "monitoring.rds.amazonaws.com" }
    }]
  })
}

# ---------- Network ----------
resource "aws_security_group" "api" {
  name        = "careloop-api"
  description = "HTTPS from inside the VPC only; no SSH"
  vpc_id      = "vpc-0123456789abcdef0"

  ingress {
    description = "HTTPS from the load balancer subnets"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [local.vpc_cidr]
  }
  egress {
    description = "HTTPS to VPC endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [local.vpc_cidr]
  }
}

resource "aws_security_group_rule" "api_attached" {
  type              = "ingress"
  description       = "Health checks"
  from_port         = 8080
  to_port           = 8080
  protocol          = "tcp"
  cidr_blocks       = [local.vpc_cidr]
  security_group_id = aws_security_group.api.id
}

# ---------- Database ----------
resource "aws_db_instance" "members" {
  identifier                          = "careloop-members"
  engine                              = "postgres"
  instance_class                      = "db.t3.medium"
  allocated_storage                   = 50
  username                            = "careloop"
  manage_master_user_password         = true
  publicly_accessible                 = false
  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.phi.arn
  multi_az                            = true
  backup_retention_period             = 14
  deletion_protection                 = true
  iam_database_authentication_enabled = true
  enabled_cloudwatch_logs_exports     = ["postgresql", "upgrade"]
  performance_insights_enabled        = true
  performance_insights_kms_key_id     = aws_kms_key.phi.arn
  monitoring_interval                 = 60
  monitoring_role_arn                 = aws_iam_role.rds_monitoring.arn
  auto_minor_version_upgrade          = true
  copy_tags_to_snapshot               = true
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "careloop-members-final"
}

# ---------- EKS ----------
resource "aws_eks_cluster" "platform" {
  name                      = "careloop-platform"
  role_arn                  = aws_iam_role.app.arn
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  vpc_config {
    subnet_ids              = ["subnet-0123456789abcdef0", "subnet-0fedcba9876543210"]
    endpoint_public_access  = false
    endpoint_private_access = true
  }
  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = aws_kms_key.phi.arn
    }
  }
}

# ---------- Audit logging ----------
resource "aws_cloudtrail" "main" {
  name                          = "careloop-main"
  s3_bucket_name                = aws_s3_bucket.audit_logs.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.phi.arn
  include_global_service_events = true
}
