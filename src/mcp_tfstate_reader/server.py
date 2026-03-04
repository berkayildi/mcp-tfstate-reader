"""MCP server that parses Terraform .tfstate files and audits for security misconfigurations."""

import json
from pathlib import Path
from typing import Any

import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server

# Sensitive ports that should not be open to the world
SENSITIVE_PORTS = {22, 3389, 5432}

app = Server("mcp-tfstate-reader")


def _load_tfstate(path: str) -> dict[str, Any]:
    """Load and parse a tfstate file, raising ValueError on failure."""
    p = Path(path)
    if not p.exists():
        raise ValueError(f"File not found: {path}")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in tfstate file: {e}") from e


def _iter_resources(state: dict[str, Any]):
    """Yield (address, type, name, values) tuples for every resource instance."""
    for resource in state.get("resources", []):
        rtype = resource.get("type", "")
        rname = resource.get("name", "")
        module = resource.get("module", "")
        for i, instance in enumerate(resource.get("instances", [])):
            index_key = instance.get("index_key")
            if index_key is not None:
                suffix = f'["{index_key}"]' if isinstance(index_key, str) else f"[{index_key}]"
            elif len(resource.get("instances", [])) > 1:
                suffix = f"[{i}]"
            else:
                suffix = ""
            if module:
                address = f"{module}.{rtype}.{rname}{suffix}"
            else:
                address = f"{rtype}.{rname}{suffix}"
            yield address, rtype, rname, instance.get("attributes", {})


# ---------------------------------------------------------------------------
# Tool: list_resources
# ---------------------------------------------------------------------------

@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="list_resources",
            description=(
                "Parse a Terraform .tfstate file and return a list of all managed resources "
                "with their addresses and resource types."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "tfstate_path": {
                        "type": "string",
                        "description": "Absolute or relative path to the .tfstate file.",
                    }
                },
                "required": ["tfstate_path"],
            },
        ),
        types.Tool(
            name="audit_security",
            description=(
                "Scan a Terraform .tfstate file for common security misconfigurations. "
                "Checks: S3 buckets without encryption or versioning, public S3 ACLs, "
                "security groups open to 0.0.0.0/0 on sensitive ports (22, 3389, 5432), "
                "IAM policies with wildcard (*) actions, unencrypted RDS/EBS volumes, "
                "publicly accessible RDS instances, public EC2 instances, Lambda functions "
                "not in a VPC, KMS keys without rotation, ElastiCache without transit "
                "encryption, unencrypted SNS/SQS, load balancers without access logs, "
                "and CloudWatch log groups without retention policies."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "tfstate_path": {
                        "type": "string",
                        "description": "Absolute or relative path to the .tfstate file.",
                    }
                },
                "required": ["tfstate_path"],
            },
        ),
        types.Tool(
            name="get_resource_detail",
            description=(
                "Return the full attributes for a specific resource identified by its address "
                "(e.g. 'aws_s3_bucket.my_bucket')."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "tfstate_path": {
                        "type": "string",
                        "description": "Absolute or relative path to the .tfstate file.",
                    },
                    "resource_address": {
                        "type": "string",
                        "description": "The resource address as shown by list_resources.",
                    },
                },
                "required": ["tfstate_path", "resource_address"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
    if name == "list_resources":
        return await _list_resources(arguments)
    if name == "audit_security":
        return await _audit_security(arguments)
    if name == "get_resource_detail":
        return await _get_resource_detail(arguments)
    raise ValueError(f"Unknown tool: {name}")


async def _list_resources(arguments: dict[str, Any]) -> list[types.TextContent]:
    path = arguments["tfstate_path"]
    state = _load_tfstate(path)

    rows: list[dict[str, str]] = []
    for address, rtype, rname, _ in _iter_resources(state):
        rows.append({"address": address, "type": rtype, "name": rname})

    if not rows:
        text = "No resources found in the state file."
    else:
        lines = [f"Found {len(rows)} resource(s):\n"]
        for r in rows:
            lines.append(f"  {r['address']}  ({r['type']})")
        text = "\n".join(lines)

    return [types.TextContent(type="text", text=text)]


async def _audit_security(arguments: dict[str, Any]) -> list[types.TextContent]:
    path = arguments["tfstate_path"]
    state = _load_tfstate(path)

    findings: list[str] = []

    for address, rtype, _, attrs in _iter_resources(state):

        # ------------------------------------------------------------------
        # S3: encryption
        # ------------------------------------------------------------------
        if rtype == "aws_s3_bucket":
            sse_config = attrs.get("server_side_encryption_configuration")
            if not sse_config:
                findings.append(
                    f"[HIGH] {address}: S3 bucket has no server-side encryption configuration."
                )

        # ------------------------------------------------------------------
        # S3: versioning
        # ------------------------------------------------------------------
        if rtype == "aws_s3_bucket":
            versioning = attrs.get("versioning")
            if not versioning or not versioning[0].get("enabled", False):
                findings.append(
                    f"[MEDIUM] {address}: S3 bucket does not have versioning enabled."
                )

        # ------------------------------------------------------------------
        # S3 ACL: public access
        # ------------------------------------------------------------------
        if rtype == "aws_s3_bucket_acl":
            acl = attrs.get("acl", "")
            if acl in ("public-read", "public-read-write"):
                findings.append(
                    f"[HIGH] {address}: S3 bucket ACL is set to '{acl}' — allows public access."
                )

        # ------------------------------------------------------------------
        # Security groups: wide-open ingress on sensitive ports
        # ------------------------------------------------------------------
        if rtype == "aws_security_group":
            ingress_rules = attrs.get("ingress", [])
            # aws_security_group stores ingress as a list of rule objects
            for rule in ingress_rules:
                cidr_blocks = rule.get("cidr_blocks", [])
                ipv6_cidr_blocks = rule.get("ipv6_cidr_blocks", [])
                from_port = rule.get("from_port", 0)
                to_port = rule.get("to_port", 0)
                open_to_world = "0.0.0.0/0" in cidr_blocks or "::/0" in ipv6_cidr_blocks
                if open_to_world:
                    for port in SENSITIVE_PORTS:
                        if isinstance(from_port, int) and isinstance(to_port, int):
                            if from_port <= port <= to_port:
                                findings.append(
                                    f"[HIGH] {address}: Security group allows 0.0.0.0/0 "
                                    f"ingress on port {port}."
                                )

        # aws_vpc_security_group_ingress_rule (separate resource style)
        if rtype == "aws_vpc_security_group_ingress_rule":
            cidr = attrs.get("cidr_ipv4", "")
            cidr6 = attrs.get("cidr_ipv6", "")
            from_port = attrs.get("from_port")
            to_port = attrs.get("to_port")
            open_to_world = cidr == "0.0.0.0/0" or cidr6 == "::/0"
            if open_to_world and from_port is not None and to_port is not None:
                for port in SENSITIVE_PORTS:
                    if from_port <= port <= to_port:
                        findings.append(
                            f"[HIGH] {address}: Security group ingress rule allows 0.0.0.0/0 "
                            f"on port {port}."
                        )

        # ------------------------------------------------------------------
        # IAM: wildcard actions
        # ------------------------------------------------------------------
        if rtype in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"):
            policy_doc_raw = attrs.get("policy")
            if policy_doc_raw:
                try:
                    policy_doc = (
                        json.loads(policy_doc_raw)
                        if isinstance(policy_doc_raw, str)
                        else policy_doc_raw
                    )
                    for stmt in policy_doc.get("Statement", []):
                        effect = stmt.get("Effect", "Allow")
                        if effect != "Allow":
                            continue
                        actions = stmt.get("Action", [])
                        if isinstance(actions, str):
                            actions = [actions]
                        if "*" in actions:
                            findings.append(
                                f"[CRITICAL] {address}: IAM policy contains a wildcard (*) "
                                "action — grants unrestricted permissions."
                            )
                            break
                except (json.JSONDecodeError, AttributeError):
                    pass

        # ------------------------------------------------------------------
        # RDS: encryption at rest
        # ------------------------------------------------------------------
        if rtype == "aws_db_instance":
            if not attrs.get("storage_encrypted", False):
                findings.append(
                    f"[HIGH] {address}: RDS instance storage is not encrypted."
                )

        # ------------------------------------------------------------------
        # RDS: publicly accessible
        # ------------------------------------------------------------------
        if rtype == "aws_db_instance":
            if attrs.get("publicly_accessible", False):
                findings.append(
                    f"[HIGH] {address}: RDS instance is publicly accessible."
                )

        # ------------------------------------------------------------------
        # EC2: public IP assignment
        # ------------------------------------------------------------------
        if rtype == "aws_instance":
            if attrs.get("associate_public_ip_address", False):
                findings.append(
                    f"[MEDIUM] {address}: EC2 instance has a public IP address assigned."
                )

        # ------------------------------------------------------------------
        # CloudWatch log groups: retention policy
        # ------------------------------------------------------------------
        if rtype == "aws_cloudwatch_log_group":
            retention = attrs.get("retention_in_days")
            if not retention:
                findings.append(
                    f"[MEDIUM] {address}: CloudWatch log group has no retention policy "
                    "(logs kept indefinitely)."
                )

        # ------------------------------------------------------------------
        # EBS: encryption
        # ------------------------------------------------------------------
        if rtype == "aws_ebs_volume":
            if not attrs.get("encrypted", False):
                findings.append(
                    f"[HIGH] {address}: EBS volume is not encrypted."
                )

        # ------------------------------------------------------------------
        # Lambda: VPC configuration
        # ------------------------------------------------------------------
        if rtype == "aws_lambda_function":
            vpc_config = attrs.get("vpc_config")
            if not vpc_config or not vpc_config[0].get("subnet_ids"):
                findings.append(
                    f"[MEDIUM] {address}: Lambda function is not deployed in a VPC."
                )

        # ------------------------------------------------------------------
        # KMS: key rotation
        # ------------------------------------------------------------------
        if rtype == "aws_kms_key":
            if not attrs.get("enable_key_rotation", False):
                findings.append(
                    f"[MEDIUM] {address}: KMS key does not have automatic key rotation enabled."
                )

        # ------------------------------------------------------------------
        # ElastiCache: transit encryption
        # ------------------------------------------------------------------
        if rtype == "aws_elasticache_replication_group":
            if not attrs.get("transit_encryption_enabled", False):
                findings.append(
                    f"[HIGH] {address}: ElastiCache replication group does not have transit encryption enabled."
                )

        # ------------------------------------------------------------------
        # SNS: encryption at rest
        # ------------------------------------------------------------------
        if rtype == "aws_sns_topic":
            if not attrs.get("kms_master_key_id"):
                findings.append(
                    f"[MEDIUM] {address}: SNS topic is not encrypted with a KMS key."
                )

        # ------------------------------------------------------------------
        # SQS: encryption at rest
        # ------------------------------------------------------------------
        if rtype == "aws_sqs_queue":
            if not attrs.get("kms_master_key_id"):
                findings.append(
                    f"[MEDIUM] {address}: SQS queue is not encrypted with a KMS key."
                )

        # ------------------------------------------------------------------
        # ALB/NLB: access logs
        # ------------------------------------------------------------------
        if rtype == "aws_lb":
            access_logs = attrs.get("access_logs")
            if not access_logs or not access_logs[0].get("enabled", False):
                findings.append(
                    f"[MEDIUM] {address}: Load balancer does not have access logs enabled."
                )

    if not findings:
        summary = "No security misconfigurations found."
    else:
        summary = f"Found {len(findings)} finding(s):\n\n" + "\n".join(findings)

    return [types.TextContent(type="text", text=summary)]


async def _get_resource_detail(arguments: dict[str, Any]) -> list[types.TextContent]:
    path = arguments["tfstate_path"]
    target = arguments["resource_address"]
    state = _load_tfstate(path)

    for address, rtype, rname, attrs in _iter_resources(state):
        if address == target:
            detail = {
                "address": address,
                "type": rtype,
                "name": rname,
                "attributes": attrs,
            }
            return [
                types.TextContent(
                    type="text",
                    text=json.dumps(detail, indent=2, default=str),
                )
            ]

    return [
        types.TextContent(
            type="text",
            text=f"Resource '{target}' not found in state file.",
        )
    ]


def main() -> None:
    import asyncio

    async def _run():
        async with stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options())

    asyncio.run(_run())


if __name__ == "__main__":
    main()
