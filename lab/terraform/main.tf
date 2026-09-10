# Cloud lab: minimal AWS-shaped graph against LocalStack (community, no auth).
# Real Terraform run, real boto3-shaped API, no cost, no external account.
# Resources map 1:1 to docs/MISCONFIG_RUBRIC.md slugs so the exported edges
# carry real p_source provenance, not synthetic gen.py sampling.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  s3_use_path_style           = true
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  endpoints {
    s3  = "http://localhost:4566"
    iam = "http://localhost:4566"
    sts = "http://localhost:4566"
    ec2 = "http://localhost:4566"
  }
}

# --- s3-public-read: S3 bucket policy open to anonymous read ---
resource "aws_s3_bucket" "public_data" {
  bucket = "itis2026-lab-public-data"
}

resource "aws_s3_bucket_policy" "public_data_read" {
  bucket = aws_s3_bucket.public_data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:GetObject"]
      Resource  = "${aws_s3_bucket.public_data.arn}/*"
    }]
  })
}

# --- iam-trust-wildcard-principal: assumable role, trust policy Principal: * ---
resource "aws_iam_role" "wildcard_trust" {
  name = "itis2026-lab-wildcard-trust-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AnyoneAssume"
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "wildcard_trust_admin" {
  name = "admin-access"
  role = aws_iam_role.wildcard_trust.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# --- iam-trust-missing-external-id: cross-account role, no sts:ExternalId condition ---
# Cartography's role-trust parser only materializes a TRUSTS_AWS_PRINCIPAL edge for a
# concrete principal ARN (see _parse_principal_entries / load order in iam.py); a bare
# `Principal: "*"` never resolves to a node to attach the edge to and is silently
# dropped. That's a real, documented upstream gap (see lab/README.md), not something
# this project patches by writing a custom collector to replace Cartography.
# This second role is the concrete-ARN case, so the exporter has a real trust edge to pull.
resource "aws_iam_role" "cross_account_trust" {
  name = "itis2026-lab-cross-account-trust-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "ExternalAccountAssume"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::999999999999:root" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "cross_account_trust_admin" {
  name = "admin-access"
  role = aws_iam_role.cross_account_trust.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# --- sg-open-mgmt-port: security group, 0.0.0.0/0 on 22/3389 ---
resource "aws_security_group" "open_mgmt" {
  name        = "itis2026-lab-open-mgmt"
  description = "lab: sg-open-mgmt-port misconfig"

  ingress {
    description = "ssh from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "rdp from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
