# ──────────────────────────────────────────────
# EC2 – XOR C2 Teamserver (Rust) via Docker
# ──────────────────────────────────────────────
resource "aws_instance" "backend" {
  ami                    = var.ec2_ami
  instance_type          = var.ec2_instance_type
  subnet_id              = data.aws_subnets.default.ids[0]
  vpc_security_group_ids = [aws_security_group.ec2.id]
  key_name               = "redteam"
  user_data              = file("")

  tags = {
    Name    = "${var.project_name}-backend"
    Project = var.project_name
  }
}
