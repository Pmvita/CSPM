data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  threat = var.enable_threat_intel ? 1 : 0
  name   = var.project_name
}
