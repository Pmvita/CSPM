import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lambda"))

import check_posture as posture  # noqa: E402


def client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "op")


def test_s3_flags_missing_public_block():
    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": [{"Name": "open-lab"}]}
    s3.get_public_access_block.side_effect = client_error("NoSuchPublicAccessBlockConfiguration")
    s3.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}
    }
    names = {item["check"] for item in posture.check_s3(s3)}
    assert "s3-public-access-block" in names
    assert "s3-encryption" not in names


def test_iam_flags_old_access_key():
    iam = MagicMock()
    iam.list_users.return_value = {"Users": [{"UserName": "alice"}]}
    iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {
                "AccessKeyId": "AKIAEXAMPLEKEYID1",
                "Status": "Active",
                "CreateDate": datetime.now(timezone.utc) - timedelta(days=120),
            }
        ]
    }
    findings = posture.check_iam_keys(iam)
    assert findings[0]["check"] == "iam-access-key-age"


def test_sg_flags_ssh_to_world():
    ec2 = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-123",
                    "IpPermissions": [
                        {
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                }
            ]
        }
    ]
    ec2.get_paginator.return_value = paginator
    findings = posture.check_security_groups(ec2)
    assert findings[0]["check"] == "sg-open-admin-port"
    assert "22" in findings[0]["detail"]


def test_root_mfa_flags_when_disabled():
    iam = MagicMock()
    iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 0}}
    findings = posture.check_root_mfa(iam)
    assert findings[0]["check"] == "root-mfa"
    assert findings[0]["severity"] == "CRITICAL"


def test_root_mfa_ok_when_enabled():
    iam = MagicMock()
    iam.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
    assert posture.check_root_mfa(iam) == []


def test_cloudtrail_flags_when_missing():
    ct = MagicMock()
    ct.describe_trails.return_value = {"trailList": []}
    findings = posture.check_cloudtrail(ct)
    assert findings[0]["check"] == "cloudtrail-enabled"


def test_cloudtrail_ok_when_logging():
    ct = MagicMock()
    ct.describe_trails.return_value = {"trailList": [{"Name": "main", "TrailARN": "arn:aws:cloudtrail:x:1:trail/main"}]}
    ct.get_trail_status.return_value = {"IsLogging": True}
    assert posture.check_cloudtrail(ct) == []


def test_ebs_default_encryption_flags_when_off():
    ec2 = MagicMock()
    ec2.get_ebs_encryption_by_default.return_value = {"EbsEncryptionByDefault": False}
    findings = posture.check_ebs_encryption(ec2)
    assert findings[0]["check"] == "ebs-default-encryption"


def test_rds_flags_public_instance():
    rds = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {
            "DBInstances": [
                {"DBInstanceIdentifier": "prod-db", "PubliclyAccessible": True},
                {"DBInstanceIdentifier": "private-db", "PubliclyAccessible": False},
            ]
        }
    ]
    rds.get_paginator.return_value = paginator
    findings = posture.check_rds_public(rds)
    assert len(findings) == 1
    assert findings[0]["resource"] == "prod-db"


def test_collect_findings_combines_checks(monkeypatch):
    monkeypatch.setattr(posture, "check_s3", lambda _c: [posture.finding("s3-encryption", "HIGH", "b", "x")])
    monkeypatch.setattr(posture, "check_iam_keys", lambda _c: [])
    monkeypatch.setattr(posture, "check_security_groups", lambda _c: [])
    monkeypatch.setattr(posture, "check_root_mfa", lambda _c: [])
    monkeypatch.setattr(posture, "check_ebs_encryption", lambda _c: [])
    monkeypatch.setattr(posture, "check_cloudtrail", lambda _c: [])
    monkeypatch.setattr(posture, "check_rds_public", lambda _c: [])
    out = posture.collect_findings(MagicMock(), MagicMock(), MagicMock(), MagicMock(), MagicMock())
    assert len(out) == 1


def test_write_findings_json_helper(tmp_path):
    payload = posture.findings_payload([posture.finding("root-mfa", "CRITICAL", "root", "off")])
    path = tmp_path / "findings.json"
    body = posture.write_findings_json(payload, str(path))
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["findingCount"] == 1
    assert '"root-mfa"' in body


def test_metric_data_includes_per_check_dimensions():
    findings = [
        posture.finding("root-mfa", "CRITICAL", "root", "off"),
        posture.finding("s3-encryption", "HIGH", "b1", "missing"),
        posture.finding("s3-encryption", "HIGH", "b2", "missing"),
    ]
    metrics = posture.metric_data_for_findings(findings)
    assert metrics[0]["MetricName"] == "FindingCount"
    assert metrics[0]["Value"] == 3.0
    by_check = {
        m["Dimensions"][0]["Value"]: m["Value"]
        for m in metrics
        if m["MetricName"] == "CheckFindingCount"
    }
    assert by_check["root-mfa"] == 1.0
    assert by_check["s3-encryption"] == 2.0
    assert by_check["cloudtrail-enabled"] == 0.0


def test_persist_findings_s3_puts_object():
    s3 = MagicMock()
    payload = posture.findings_payload([])
    key = posture.persist_findings_s3(s3, "cspm-findings", payload)
    assert key.startswith("findings/")
    s3.put_object.assert_called_once()
    kwargs = s3.put_object.call_args.kwargs
    assert kwargs["Bucket"] == "cspm-findings"
    assert kwargs["ContentType"] == "application/json"
