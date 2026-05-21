variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used as prefix for resources"
  type        = string
  default     = "lambda-ec2-proxy"
}

variable "ec2_instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t2.medium"
}

variable "ec2_ami" {
  description = "Ubuntu 24.04 LTS AMI (us-east-1)"
  type        = string
  default     = "ami-0e86e20dae9224db8"
}

variable "ec2_http_port" {
  description = "Port on which EC2 HTTP server listens"
  type        = number
  default     = 8088
}

variable "ssh_allowed_cidr" {
  description = "CIDR allowed to SSH into EC2 (restrict in production)"
  type        = string
  default     = "0.0.0.0/0"
}
