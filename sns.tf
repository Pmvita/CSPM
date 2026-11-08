resource "aws_sns_topic" "findings" {
  name = "${local.name}-findings"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.findings.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_budgets_budget" "lab" {
  name         = "${local.name}-lab"
  budget_type  = "COST"
  limit_amount = tostring(var.budget_amount)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }
}
