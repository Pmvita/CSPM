# ✅ CSPM — TODO

**Spec version:** 2.0 — 2026-09-18 (same version as [`README.md`](./README.md))

This checklist **is** the whole project. README = design; this file = build list.

**Locked scope:**

- S3 PAB + encryption, IAM key age, SG 22/3389 to the world
- SNS email, 7-day logs, one FindingCount alarm
- Terraform, no Config, no committed state
- `enable_threat_intel = false` unless you will destroy the same day

---

## 💰 Cost guard

- [x] $1 monthly budget + email
- [ ] Confirm SNS subscription
- [ ] `terraform destroy` after each demo window

---

## 🏗️ Project setup

- [x] Terraform layout + `.gitignore` for state
- [x] Python 3.12 Lambda + pytest
- [x] MIT LICENSE

---

## λ Scan

- [x] S3 public access block
- [x] S3 default encryption
- [x] IAM access keys older than 90 days
- [x] Security groups with 22/3389 to `0.0.0.0/0`
- [x] JSON log line with finding count
- [x] SNS publish of the finding list
- [x] `CSPM/FindingCount` metric

---

## 🔑 IAM

- [x] One role
- [x] SNS publish locked to the topic ARN
- [x] CloudWatch PutMetricData locked to namespace CSPM

---

## 🔬 Observability

- [x] Log group, 7-day retention
- [x] Alarm on FindingCount > 0 → SNS

---

## 🧪 Tests

- [x] Unit tests for S3 / IAM / SG findings
- [ ] Manual `aws lambda invoke` after apply

---

## 🛡️ Opt-in threat intel (off by default)

- [x] GuardDuty detector behind `enable_threat_intel`
- [x] SecurityHub account behind the same flag
- [ ] Do not apply with the flag true unless destroy is scheduled the same day
