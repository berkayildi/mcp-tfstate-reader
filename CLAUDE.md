# CLAUDE.md — mcp-tfstate-reader

This file helps Claude Code understand the project structure and conventions for future sessions.

## Project overview

**mcp-tfstate-reader** is a local MCP (Model Context Protocol) server written in Python. It parses Terraform `.tfstate` files and exposes five tools that allow AI agents to audit infrastructure for security misconfigurations without needing live cloud credentials.

Transport: **stdio** (standard input/output).

---

## Directory structure

```
mcp-tfstate-reader/
├── src/
│   └── mcp_tfstate_reader/
│       ├── __init__.py          # Package version
│       └── server.py            # All MCP tool logic (single file)
├── tests/
│   ├── __init__.py
│   ├── fixtures/
│   │   └── sample.tfstate       # Comprehensive fixture covering all audit rules
│   └── test_server.py           # pytest tests — imports internals directly
├── pyproject.toml               # Build config (hatchling), deps, pytest settings
├── Makefile                     # setup / build / start / test / clean
├── README.md                    # User-facing docs with MCP config examples
├── CLAUDE.md                    # This file
└── .gitignore
```

---

## Key design decisions

1. **Single-file server** — all tool logic lives in `src/mcp_tfstate_reader/server.py`. Keep it that way unless the file exceeds ~500 lines.

2. **No external dependencies** beyond `mcp` SDK for runtime, and `pytest` + `pytest-asyncio` for tests. Do not add `boto3`, `pydantic`, or other libraries without a strong reason.

3. **Private helpers are directly importable in tests** — the test file imports `_load_tfstate`, `_iter_resources`, `_list_resources`, `_audit_security`, `_get_resource_detail`, `_summarize_state`, and `_compare_states` directly. Keep these functions at module level.

4. **`asyncio_mode = "auto"`** is set in `pyproject.toml`, so `@pytest.mark.asyncio` is optional but harmless to include.

5. **Resource address format** follows Terraform convention: `<type>.<name>` for root module, `<module>.<type>.<name>` for nested modules. Index suffixes (`[0]`, `["key"]`) are appended for multi-instance resources.

---

## Sensitive ports (audit_security)

```python
SENSITIVE_PORTS = {22, 3389, 5432}
```

To add more ports, update this set in `server.py` and add corresponding test cases in `test_server.py`.

## Audit categories

The `_audit_security` function checks 16 resource types across these categories:

- **S3** — encryption, versioning, public ACLs (`aws_s3_bucket`, `aws_s3_bucket_acl`)
- **Security Groups** — open ingress on sensitive ports (`aws_security_group`, `aws_vpc_security_group_ingress_rule`)
- **IAM** — wildcard actions (`aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`)
- **RDS** — encryption at rest, public accessibility (`aws_db_instance`)
- **EBS** — volume encryption (`aws_ebs_volume`)
- **EC2** — public IP assignment (`aws_instance`)
- **Lambda** — VPC configuration (`aws_lambda_function`)
- **KMS** — key rotation (`aws_kms_key`)
- **ElastiCache** — transit encryption (`aws_elasticache_replication_group`)
- **SNS** — KMS encryption (`aws_sns_topic`)
- **SQS** — KMS encryption (`aws_sqs_queue`)
- **ALB/NLB** — access logs (`aws_lb`)
- **CloudWatch** — log retention (`aws_cloudwatch_log_group`)

---

## Adding a new audit check

1. Add a new `if rtype == "aws_something":` block inside the `_audit_security` function loop.
2. Append findings to the `findings: list[str]` list using the format:
   `[SEVERITY] address: description.`
   Valid severities: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
3. Add a fixture resource to `tests/fixtures/sample.tfstate` (both a "bad" and a "good" variant).
4. Add two tests to `test_server.py`: one asserting the bad resource IS flagged, one asserting the good resource is NOT.

---

## Running the server manually

```bash
make setup    # create venv + install deps
make start    # python -m mcp_tfstate_reader.server (stdio mode)
make test     # pytest tests/ -v
```

---

## MCP tool signatures

| Tool | Required inputs | Returns |
|------|----------------|---------|
| `list_resources` | `tfstate_path: str` | Plain text list of addresses |
| `audit_security` | `tfstate_path: str` | Plain text list of findings or "No findings" |
| `get_resource_detail` | `tfstate_path: str`, `resource_address: str` | JSON string of resource attributes |
| `summarize_state` | `tfstate_path: str` | Plain text summary (counts by type/module, providers, tags, regions) |
| `compare_states` | `tfstate_path_old: str`, `tfstate_path_new: str` | Plain text diff report (added/removed/modified) |
