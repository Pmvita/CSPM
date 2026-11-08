data "archive_file" "scan" {
  type        = "zip"
  source_file = "${path.module}/lambda/check_posture.py"
  output_path = "${path.module}/lambda/check_posture.zip"
}

resource "aws_lambda_function" "scan" {
  function_name    = "${local.name}-scan"
  role             = aws_iam_role.scan.arn
  filename         = data.archive_file.scan.output_path
  source_code_hash = data.archive_file.scan.output_base64sha256
  handler          = "check_posture.handler"
  runtime          = "python3.12"
  timeout          = 60
  memory_size      = 256

  environment {
    variables = merge(
      {
        FINDINGS_TOPIC_ARN = aws_sns_topic.findings.arn
      },
      var.findings_bucket_name == null ? {} : {
        FINDINGS_BUCKET = var.findings_bucket_name
      }
    )
  }

  depends_on = [aws_cloudwatch_log_group.scan]
}

resource "aws_cloudwatch_log_group" "scan" {
  name              = "/aws/lambda/${local.name}-scan"
  retention_in_days = 7
}

resource "aws_cloudwatch_event_rule" "daily" {
  name                = "${local.name}-daily"
  schedule_expression = "rate(${var.scan_rate_hours} hours)"
}

resource "aws_cloudwatch_event_target" "scan" {
  rule = aws_cloudwatch_event_rule.daily.name
  arn  = aws_lambda_function.scan.arn
}

resource "aws_lambda_permission" "events" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scan.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily.arn
}

resource "aws_cloudwatch_metric_alarm" "findings" {
  alarm_name          = "${local.name}-findings"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FindingCount"
  namespace           = "CSPM"
  period              = 86400
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "Posture scan reported at least one finding."
  alarm_actions       = [aws_sns_topic.findings.arn]
  treat_missing_data  = "notBreaching"
}
