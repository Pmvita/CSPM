resource "aws_guardduty_detector" "this" {
  count  = local.threat
  enable = true
}

resource "aws_securityhub_account" "this" {
  count = local.threat
}

output "findings_topic_arn" {
  value = aws_sns_topic.findings.arn
}

output "scan_function_name" {
  value = aws_lambda_function.scan.function_name
}

output "threat_intel_enabled" {
  value = var.enable_threat_intel
}
