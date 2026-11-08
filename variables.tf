variable "project_name" {
  type    = string
  default = "cspm"
}

variable "aws_region" {
  type    = string
  default = "ca-central-1"
}

variable "alert_email" {
  type        = string
  description = "SNS email that receives posture findings. Confirm the subscription before the first run."
}

variable "scan_rate_hours" {
  type    = number
  default = 24
}

variable "enable_threat_intel" {
  type        = bool
  default     = false
  description = "Opt-in GuardDuty + SecurityHub. These bill after the trial. Leave false for the $0 lab."
}

variable "budget_amount" {
  type    = number
  default = 1
}

variable "findings_bucket_name" {
  type        = string
  default     = null
  description = "Optional existing S3 bucket for JSON finding archives. Leave null to skip persistence."
}
