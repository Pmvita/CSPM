# ✅ CSPM — TODO

**Spec version:** 2.1 — 2026-11-08 (same version as [`README.md`](./README.md))

This checklist **is** the whole project. README = design; this file = build list.

**Locked scope:**

- Eight checks: S3 PAB, S3 encryption, IAM key age, SG 22/3389, root MFA, CloudTrail, EBS default encryption, RDS public access
- SNS email, 7-day logs, one FindingCount alarm
- Terraform, no Config, no committed state
- `enable_threat_intel = false` unless you will destroy the same day

---

## 💰 Cost guard

- [x] $1 monthly budget + email
- [ ] Confirm SNS subscription — **needs live apply + inbox confirm**
- [ ] `terraform destroy` after each demo window — **after apply only**

---

## 🏗️ Project setup

- [x] Terraform layout + `.gitignore` for state
- [x] Python 3.12 Lambda + pytest (local: `Python312` / CI installs 3.12)
- [x] MIT LICENSE

---

## λ Scan (8 checks — match README)

- [x] S3 public access block
- [x] S3 default encryption
- [x] IAM access keys older than 90 days
- [x] Security groups with 22/3389 to `0.0.0.0/0`
- [x] Root MFA
- [x] CloudTrail enabled / logging
- [x] EBS default encryption
- [x] RDS publicly accessible
- [x] JSON log line with finding count
- [x] SNS publish of the finding list
- [x] `CSPM/FindingCount` metric (+ per-check counts)

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

- [x] Unit tests for posture checks (`pytest` — 13 passed locally on Python 3.12; CI is also source of truth)
- [ ] Manual `aws lambda invoke` after apply — **pending AWS credentials**

---

## 🛡️ Opt-in threat intel (off by default)

- [x] GuardDuty detector behind `enable_threat_intel`
- [x] SecurityHub account behind the same flag
- [ ] Do not apply with the flag true unless destroy is scheduled the same day

**Status (2026-11-08):** Code + unit tests complete (8 checks). Live `terraform apply` → SNS confirm → `aws lambda invoke` → `destroy` blocked until AWS credentials exist. Ignore `CSPM-rebuild-v2`.

---

*Last updated: 2026-11-08*
