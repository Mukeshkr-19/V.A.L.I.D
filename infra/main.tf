terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "ami_id" {
  type        = string
  description = "AMI for the web instance; supplied at deploy time."
}

variable "db_password" {
  type        = string
  description = "Database master password; supplied at deploy time."
  sensitive   = true
}

resource "aws_security_group" "web" {
  name        = "web"
  description = "Web tier access"

  ingress {
    description = "SSH from the internal admin network"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  tags = {
    owner       = "platform-team"
    environment = "production"
  }
}

resource "aws_instance" "web" {
  ami                    = var.ami_id
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.web.id]

  tags = {
    owner       = "platform-team"
    environment = "production"
  }
}

resource "aws_db_instance" "main" {
  identifier          = "main"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "app"
  password            = var.db_password
  skip_final_snapshot = true
  deletion_protection = true

  tags = {
    owner       = "platform-team"
    environment = "production"
  }
}
