data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "scan" {
  statement {
    sid = "Logs"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.scan.arn}:*"]
  }

  statement {
    sid = "S3Posture"
    actions = [
      "s3:ListAllMyBuckets",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetEncryptionConfiguration",
    ]
    resources = ["*"]
  }

  statement {
    sid = "IamKeys"
    actions = [
      "iam:ListUsers",
      "iam:ListAccessKeys",
      "iam:GetAccountSummary",
    ]
    resources = ["*"]
  }

  statement {
    sid = "Ec2Posture"
    actions = [
      "ec2:DescribeSecurityGroups",
      "ec2:GetEbsEncryptionByDefault",
    ]
    resources = ["*"]
  }

  statement {
    sid = "CloudTrailRead"
    actions = [
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "RdsRead"
    actions   = ["rds:DescribeDBInstances"]
    resources = ["*"]
  }

  statement {
    sid       = "Notify"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.findings.arn]
  }

  statement {
    sid       = "Metric"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["CSPM"]
    }
  }

  dynamic "statement" {
    for_each = var.findings_bucket_name == null ? [] : [1]
    content {
      sid       = "FindingsPersist"
      actions   = ["s3:PutObject"]
      resources = ["arn:aws:s3:::${var.findings_bucket_name}/findings/*"]
    }
  }
}

resource "aws_iam_role" "scan" {
  name               = "${local.name}-scan"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy" "scan" {
  name   = "${local.name}-scan"
  role   = aws_iam_role.scan.id
  policy = data.aws_iam_policy_document.scan.json
}
