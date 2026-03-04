"""Tests for mcp_tfstate_reader.server — list_resources, audit_security, get_resource_detail."""

import json
import pytest
from pathlib import Path

# Import internal helpers directly so we can test logic without spinning up the MCP transport.
from mcp_tfstate_reader.server import (
    _load_tfstate,
    _iter_resources,
    _list_resources,
    _audit_security,
    _get_resource_detail,
)

FIXTURE = str(Path(__file__).parent / "fixtures" / "sample.tfstate")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _text(result) -> str:
    """Extract the text content from a tool result list."""
    return result[0].text


# ---------------------------------------------------------------------------
# _load_tfstate
# ---------------------------------------------------------------------------

def test_load_tfstate_success():
    state = _load_tfstate(FIXTURE)
    assert state["version"] == 4
    assert "resources" in state


def test_load_tfstate_missing_file(tmp_path):
    with pytest.raises(ValueError, match="File not found"):
        _load_tfstate(str(tmp_path / "ghost.tfstate"))


def test_load_tfstate_invalid_json(tmp_path):
    bad = tmp_path / "bad.tfstate"
    bad.write_text("not json")
    with pytest.raises(ValueError, match="Invalid JSON"):
        _load_tfstate(str(bad))


# ---------------------------------------------------------------------------
# _iter_resources
# ---------------------------------------------------------------------------

def test_iter_resources_returns_all():
    state = _load_tfstate(FIXTURE)
    addresses = [addr for addr, *_ in _iter_resources(state)]
    assert "aws_s3_bucket.unencrypted_bucket" in addresses
    assert "aws_s3_bucket.encrypted_bucket" in addresses
    assert "aws_security_group.open_ssh" in addresses
    assert "aws_iam_policy.wildcard_policy" in addresses


# ---------------------------------------------------------------------------
# list_resources
# ---------------------------------------------------------------------------

async def test_list_resources_counts():
    result = await _list_resources({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "Found 33 resource(s)" in text


async def test_list_resources_contains_addresses():
    result = await _list_resources({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_s3_bucket.unencrypted_bucket" in text
    assert "aws_security_group.open_ssh" in text
    assert "aws_iam_policy.wildcard_policy" in text


async def test_list_resources_empty_state(tmp_path):
    empty = tmp_path / "empty.tfstate"
    empty.write_text(json.dumps({"version": 4, "resources": []}))
    result = await _list_resources({"tfstate_path": str(empty)})
    assert "No resources found" in _text(result)


# ---------------------------------------------------------------------------
# audit_security — S3
# ---------------------------------------------------------------------------

async def test_audit_s3_unencrypted_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_s3_bucket.unencrypted_bucket" in text
    assert "no server-side encryption" in text


async def test_audit_s3_encrypted_not_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    # encrypted_bucket should NOT appear in findings
    assert "aws_s3_bucket.encrypted_bucket" not in text


# ---------------------------------------------------------------------------
# audit_security — Security groups
# ---------------------------------------------------------------------------

async def test_audit_sg_open_ssh_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_security_group.open_ssh" in text
    assert "port 22" in text


async def test_audit_sg_open_rdp_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_security_group.open_rdp" in text
    assert "port 3389" in text


async def test_audit_sg_restricted_not_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_security_group.restricted" not in text


# ---------------------------------------------------------------------------
# audit_security — IAM
# ---------------------------------------------------------------------------

async def test_audit_iam_wildcard_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_iam_policy.wildcard_policy" in text
    assert "wildcard" in text.lower()


async def test_audit_iam_scoped_not_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_iam_policy.scoped_policy" not in text


# ---------------------------------------------------------------------------
# audit_security — RDS
# ---------------------------------------------------------------------------

async def test_audit_rds_unencrypted_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_db_instance.unencrypted_db" in text
    assert "not encrypted" in text


async def test_audit_rds_encrypted_not_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_db_instance.encrypted_db" not in text


# ---------------------------------------------------------------------------
# audit_security — EC2
# ---------------------------------------------------------------------------

async def test_audit_ec2_public_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_instance.public_ec2" in text
    assert "public IP" in text


async def test_audit_ec2_private_not_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_instance.private_ec2" not in text


# ---------------------------------------------------------------------------
# audit_security — CloudWatch
# ---------------------------------------------------------------------------

async def test_audit_cloudwatch_no_retention_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_cloudwatch_log_group.no_retention" in text
    assert "retention" in text.lower()


async def test_audit_cloudwatch_with_retention_not_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_cloudwatch_log_group.with_retention" not in text


# ---------------------------------------------------------------------------
# audit_security — EBS
# ---------------------------------------------------------------------------

async def test_audit_ebs_unencrypted_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_ebs_volume.unencrypted_ebs" in text
    assert "not encrypted" in text


async def test_audit_ebs_encrypted_not_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_ebs_volume.encrypted_ebs" not in text


# ---------------------------------------------------------------------------
# audit_security — S3 versioning
# ---------------------------------------------------------------------------

async def test_audit_s3_unversioned_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_s3_bucket.unversioned_bucket" in text
    assert "versioning" in text.lower()


async def test_audit_s3_versioned_not_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_s3_bucket.versioned_bucket" not in text


# ---------------------------------------------------------------------------
# audit_security — S3 ACL
# ---------------------------------------------------------------------------

async def test_audit_s3_acl_public_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_s3_bucket_acl.public_acl" in text
    assert "public" in text.lower()


async def test_audit_s3_acl_private_not_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_s3_bucket_acl.private_acl" not in text


# ---------------------------------------------------------------------------
# audit_security — RDS publicly accessible
# ---------------------------------------------------------------------------

async def test_audit_rds_public_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_db_instance.public_db" in text
    assert "publicly accessible" in text


async def test_audit_rds_private_not_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_db_instance.private_db" not in text


# ---------------------------------------------------------------------------
# audit_security — Lambda VPC
# ---------------------------------------------------------------------------

async def test_audit_lambda_no_vpc_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_lambda_function.no_vpc_lambda" in text
    assert "VPC" in text


async def test_audit_lambda_vpc_not_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_lambda_function.vpc_lambda" not in text


# ---------------------------------------------------------------------------
# audit_security — KMS key rotation
# ---------------------------------------------------------------------------

async def test_audit_kms_no_rotation_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_kms_key.no_rotation_key" in text
    assert "rotation" in text.lower()


async def test_audit_kms_rotation_not_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_kms_key.rotation_key" not in text


# ---------------------------------------------------------------------------
# audit_security — ElastiCache transit encryption
# ---------------------------------------------------------------------------

async def test_audit_elasticache_unencrypted_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_elasticache_replication_group.unencrypted_cache" in text
    assert "transit encryption" in text


async def test_audit_elasticache_encrypted_not_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_elasticache_replication_group.encrypted_cache" not in text


# ---------------------------------------------------------------------------
# audit_security — SNS encryption
# ---------------------------------------------------------------------------

async def test_audit_sns_unencrypted_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_sns_topic.unencrypted_sns" in text
    assert "KMS" in text


async def test_audit_sns_encrypted_not_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_sns_topic.encrypted_sns" not in text


# ---------------------------------------------------------------------------
# audit_security — SQS encryption
# ---------------------------------------------------------------------------

async def test_audit_sqs_unencrypted_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_sqs_queue.unencrypted_sqs" in text
    assert "KMS" in text


async def test_audit_sqs_encrypted_not_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_sqs_queue.encrypted_sqs" not in text


# ---------------------------------------------------------------------------
# audit_security — Load balancer access logs
# ---------------------------------------------------------------------------

async def test_audit_lb_no_logs_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_lb.no_logs_lb" in text
    assert "access logs" in text


async def test_audit_lb_logs_not_flagged():
    result = await _audit_security({"tfstate_path": FIXTURE})
    text = _text(result)
    assert "aws_lb.logs_lb" not in text


async def test_audit_clean_state_no_findings(tmp_path):
    clean = {
        "version": 4,
        "resources": [
            {
                "mode": "managed",
                "type": "aws_s3_bucket",
                "name": "safe",
                "instances": [
                    {
                        "attributes": {
                            "id": "safe-bucket",
                            "server_side_encryption_configuration": [{"rule": []}],
                            "versioning": [{"enabled": True, "mfa_delete": False}],
                        }
                    }
                ],
            }
        ],
    }
    p = tmp_path / "clean.tfstate"
    p.write_text(json.dumps(clean))
    result = await _audit_security({"tfstate_path": str(p)})
    assert "No security misconfigurations found" in _text(result)


# ---------------------------------------------------------------------------
# get_resource_detail
# ---------------------------------------------------------------------------

async def test_get_resource_detail_found():
    result = await _get_resource_detail(
        {"tfstate_path": FIXTURE, "resource_address": "aws_s3_bucket.unencrypted_bucket"}
    )
    text = _text(result)
    data = json.loads(text)
    assert data["address"] == "aws_s3_bucket.unencrypted_bucket"
    assert data["type"] == "aws_s3_bucket"
    assert data["attributes"]["bucket"] == "my-unencrypted-bucket"


async def test_get_resource_detail_not_found():
    result = await _get_resource_detail(
        {"tfstate_path": FIXTURE, "resource_address": "aws_s3_bucket.ghost"}
    )
    assert "not found" in _text(result)
