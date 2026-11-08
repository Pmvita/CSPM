# CSPM

### Scheduled posture checks. Findings get emailed. Nothing gets auto-fixed.

v2 of [Pmvita/aws-CSPM](https://github.com/Pmvita/aws-CSPM). The old repo turned on GuardDuty, SecurityHub, and Config and committed Terraform state. This lab runs **eight account checks** on a schedule and keeps threat intel **off**.

![Terraform](https://img.shields.io/badge/IaC-Terraform-7B42BC?logo=terraform&logoColor=white)
![Lambda](https://img.shields.io/badge/Compute-Lambda-FF9900?logo=awslambda&logoColor=white)
![SNS](https://img.shields.io/badge/Alerts-SNS%20email-FF4F8B?logo=amazon-aws&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

---

**Spec version:** 2.1 — 2026-11-08

## Details

This is a Cloud Security Posture Management lab. Once a day it looks at an AWS account for known-bad setups, emails you if it finds any, and raises an alarm. Findings are **detect-only** — nothing is auto-remediated.

```
EventBridge (once a day)
        │
        ▼
   Lambda — eight checks ──► SNS email
        │
        ├──► CloudWatch FindingCount + per-check CheckFindingCount
        └──► optional S3 JSON archive (FINDINGS_BUCKET)
```

### Checks


| What I look at         | Bad if                                          |
| ---------------------- | ----------------------------------------------- |
| S3 public-access block | A bucket is missing the full block, or has none |
| S3 default encryption  | A bucket has no encryption at rest              |
| IAM access keys        | A key is older than 90 days                     |
| Security groups        | Port 22 or 3389 is open to `0.0.0.0/0`          |
| Root MFA               | Account MFA is not enabled on the root user     |
| CloudTrail             | No trail is actively logging                    |
| EBS default encryption | EBS encryption by default is off                |
| RDS public access      | An RDS instance is publicly accessible          |


Each hit is a finding. Total count and per-check counts go to CloudWatch namespace `CSPM`. If `FindingCount > 0`, SNS fires.

## Locked scope

- Notify: SNS **email** only
- Logs: 7-day retention
- One alarm: `FindingCount > 0`
- IaC: Terraform
- Optional JSON persistence via `findings_bucket_name` (existing bucket; PutObject to `findings/*`)
- No AWS Config recorder (it bills)
- No committed `.tfstate`
- No AWS SAM — plain Lambda zip via Terraform `archive` provider

## Default cost

Lambda + EventBridge + SNS + CloudWatch logs/alarms + a $1 budget. Idle is effectively $0 on the free tier if you `terraform destroy` after the demo.

`enable_threat_intel = true` turns on GuardDuty and SecurityHub. Those are **not** free after the trial.

## Getting started

```bash
cp terraform.tfvars.example terraform.tfvars   # set alert_email
terraform init
terraform plan
terraform apply
# confirm the SNS email
aws lambda invoke --function-name cspm-scan out.json
terraform destroy
```

Tests (no AWS) — preferred path is CI (GitHub Actions installs Python 3.12 + runs `pytest`). Locally, if you have a real Python (not the Windows Store stub):

```bash
pip install -r requirements-dev.txt
pytest -q
```

CI runs `terraform fmt/validate` and `pytest` on every push/PR.

## License

MIT
