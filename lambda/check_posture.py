"""Account posture checks. Findings go to SNS and CloudWatch — they are not auto-remediated."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

MAX_KEY_AGE_DAYS = 90
OPEN_PORTS = {22, 3389}

CHECK_NAMES = (
    "s3-public-access-block",
    "s3-encryption",
    "iam-access-key-age",
    "sg-open-admin-port",
    "root-mfa",
    "cloudtrail-enabled",
    "ebs-default-encryption",
    "rds-publicly-accessible",
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def key_age_days(create_date: datetime) -> int:
    created = create_date if create_date.tzinfo else create_date.replace(tzinfo=timezone.utc)
    return (utc_now() - created).days


def finding(check: str, severity: str, resource: str, detail: str) -> dict[str, str]:
    return {
        "check": check,
        "severity": severity,
        "resource": resource,
        "detail": detail,
    }


def check_s3(s3_client) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    buckets = s3_client.list_buckets().get("Buckets", [])
    for bucket in buckets:
        name = bucket["Name"]
        try:
            pab = s3_client.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if not all(
                [
                    pab.get("BlockPublicAcls"),
                    pab.get("IgnorePublicAcls"),
                    pab.get("BlockPublicPolicy"),
                    pab.get("RestrictPublicBuckets"),
                ]
            ):
                findings.append(
                    finding("s3-public-access-block", "HIGH", name, "Public access block is not fully on.")
                )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {"NoSuchPublicAccessBlockConfiguration", "NoSuchConfiguration"}:
                findings.append(
                    finding("s3-public-access-block", "HIGH", name, "No public access block configuration.")
                )
            else:
                findings.append(finding("s3-public-access-block", "MEDIUM", name, f"Could not read PAB: {code}"))

        try:
            enc = s3_client.get_bucket_encryption(Bucket=name)
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if not rules:
                findings.append(finding("s3-encryption", "HIGH", name, "Default encryption is missing."))
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {"ServerSideEncryptionConfigurationNotFoundError", "NoSuchEncryptionConfiguration"}:
                findings.append(finding("s3-encryption", "HIGH", name, "Default encryption is missing."))
            else:
                findings.append(finding("s3-encryption", "MEDIUM", name, f"Could not read encryption: {code}"))
    return findings


def check_iam_keys(iam_client) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    users = iam_client.list_users().get("Users", [])
    for user in users:
        name = user["UserName"]
        keys = iam_client.list_access_keys(UserName=name).get("AccessKeyMetadata", [])
        for key in keys:
            if key.get("Status") != "Active":
                continue
            age = key_age_days(key["CreateDate"])
            if age > MAX_KEY_AGE_DAYS:
                findings.append(
                    finding(
                        "iam-access-key-age",
                        "MEDIUM",
                        f"{name}/{key['AccessKeyId'][-4:]}",
                        f"Active access key is {age} days old (limit {MAX_KEY_AGE_DAYS}).",
                    )
                )
    return findings


def check_security_groups(ec2_client) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    pages = ec2_client.get_paginator("describe_security_groups").paginate()
    for page in pages:
        for group in page.get("SecurityGroups", []):
            group_id = group["GroupId"]
            for perm in group.get("IpPermissions", []):
                from_port = perm.get("FromPort")
                to_port = perm.get("ToPort")
                if from_port is None or to_port is None:
                    continue
                open_range = set(range(from_port, to_port + 1)) & OPEN_PORTS
                if not open_range:
                    continue
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        findings.append(
                            finding(
                                "sg-open-admin-port",
                                "HIGH",
                                group_id,
                                f"Ports {sorted(open_range)} open to 0.0.0.0/0.",
                            )
                        )
    return findings


def check_root_mfa(iam_client) -> list[dict[str, str]]:
    summary = iam_client.get_account_summary().get("SummaryMap", {})
    if summary.get("AccountMFAEnabled", 0) != 1:
        return [
            finding(
                "root-mfa",
                "CRITICAL",
                "root",
                "Root account MFA is not enabled.",
            )
        ]
    return []


def check_cloudtrail(ct_client) -> list[dict[str, str]]:
    trails = ct_client.describe_trails(includeShadowTrails=False).get("trailList", [])
    if not trails:
        return [
            finding(
                "cloudtrail-enabled",
                "HIGH",
                "account",
                "No CloudTrail trails are configured.",
            )
        ]

    findings: list[dict[str, str]] = []
    any_logging = False
    for trail in trails:
        name = trail.get("Name") or trail.get("TrailARN") or "unknown"
        status = ct_client.get_trail_status(Name=trail.get("TrailARN") or name)
        if status.get("IsLogging"):
            any_logging = True
        else:
            findings.append(
                finding(
                    "cloudtrail-enabled",
                    "HIGH",
                    name,
                    "CloudTrail trail exists but logging is stopped.",
                )
            )
    if not any_logging and not findings:
        findings.append(
            finding(
                "cloudtrail-enabled",
                "HIGH",
                "account",
                "No CloudTrail trail is actively logging.",
            )
        )
    elif any_logging:
        # Drop per-trail stopped findings if at least one trail logs (multi-region/org setups).
        findings = [f for f in findings if f["check"] != "cloudtrail-enabled"]
    return findings


def check_ebs_encryption(ec2_client) -> list[dict[str, str]]:
    status = ec2_client.get_ebs_encryption_by_default()
    if not status.get("EbsEncryptionByDefault"):
        return [
            finding(
                "ebs-default-encryption",
                "HIGH",
                "account",
                "EBS encryption by default is disabled.",
            )
        ]
    return []


def check_rds_public(rds_client) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    pages = rds_client.get_paginator("describe_db_instances").paginate()
    for page in pages:
        for db in page.get("DBInstances", []):
            if db.get("PubliclyAccessible"):
                findings.append(
                    finding(
                        "rds-publicly-accessible",
                        "HIGH",
                        db.get("DBInstanceIdentifier", "unknown"),
                        "RDS instance is publicly accessible.",
                    )
                )
    return findings


def collect_findings(
    s3_client,
    iam_client,
    ec2_client,
    ct_client=None,
    rds_client=None,
) -> list[dict[str, str]]:
    findings = (
        check_s3(s3_client)
        + check_iam_keys(iam_client)
        + check_security_groups(ec2_client)
        + check_root_mfa(iam_client)
        + check_ebs_encryption(ec2_client)
    )
    if ct_client is not None:
        findings += check_cloudtrail(ct_client)
    if rds_client is not None:
        findings += check_rds_public(rds_client)
    return findings


def findings_payload(findings: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "source": "cspm-posture",
        "checkedAt": utc_now().isoformat(),
        "findingCount": len(findings),
        "findings": findings,
    }


def write_findings_json(payload: dict[str, Any], path: str | None = None) -> str:
    """Serialize findings to a JSON string, optionally writing to a local path (tests/helpers)."""
    body = json.dumps(payload, indent=2)
    if path:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(body)
    return body


def persist_findings_s3(s3_client, bucket: str, payload: dict[str, Any], prefix: str = "findings") -> str:
    key = f"{prefix}/{payload['checkedAt'].replace(':', '-')}.json"
    body = write_findings_json(payload)
    s3_client.put_object(
        Bucket=bucket,
        Key=key,
        Body=body.encode("utf-8"),
        ContentType="application/json",
    )
    return key


def metric_data_for_findings(findings: list[dict[str, str]]) -> list[dict[str, Any]]:
    counts = {name: 0 for name in CHECK_NAMES}
    for item in findings:
        check = item.get("check", "")
        if check in counts:
            counts[check] += 1

    metrics: list[dict[str, Any]] = [
        {
            "MetricName": "FindingCount",
            "Value": float(len(findings)),
            "Unit": "Count",
        }
    ]
    for check_name, count in counts.items():
        metrics.append(
            {
                "MetricName": "CheckFindingCount",
                "Dimensions": [{"Name": "Check", "Value": check_name}],
                "Value": float(count),
                "Unit": "Count",
            }
        )
    return metrics


def publish(
    findings: list[dict[str, str]],
    sns_client,
    cw_client,
    topic_arn: str,
    region: str,
    s3_client=None,
    findings_bucket: str | None = None,
) -> dict[str, Any]:
    payload = findings_payload(findings)
    print(json.dumps({"stage": "scan", "result": "ok", "findingCount": len(findings)}))
    sns_client.publish(
        TopicArn=topic_arn,
        Subject=f"CSPM posture: {len(findings)} finding(s)",
        Message=write_findings_json(payload),
    )
    cw_client.put_metric_data(Namespace="CSPM", MetricData=metric_data_for_findings(findings))

    s3_key = None
    if findings_bucket and s3_client is not None:
        s3_key = persist_findings_s3(s3_client, findings_bucket, payload)
        print(json.dumps({"stage": "persist", "bucket": findings_bucket, "key": s3_key}))

    return {"payload": payload, "s3Key": s3_key}


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    region = os.environ["AWS_REGION"]
    topic_arn = os.environ["FINDINGS_TOPIC_ARN"]
    findings_bucket = os.environ.get("FINDINGS_BUCKET") or None
    session = boto3.session.Session(region_name=region)
    s3_client = session.client("s3")
    findings = collect_findings(
        s3_client,
        session.client("iam"),
        session.client("ec2"),
        session.client("cloudtrail"),
        session.client("rds"),
    )
    result = publish(
        findings,
        session.client("sns"),
        session.client("cloudwatch"),
        topic_arn,
        region,
        s3_client=s3_client,
        findings_bucket=findings_bucket,
    )
    return {
        "findingCount": len(findings),
        "findings": findings,
        "s3Key": result.get("s3Key"),
    }
