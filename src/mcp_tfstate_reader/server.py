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
        types.Tool(
            name="summarize_state",
            description=(
                "Provide a high-level overview of a Terraform state file: total resource count, "
                "counts by type and module, providers in use, tagged vs untagged resources, "
                "and unique regions."
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
            name="compare_states",
            description=(
                "Compare two Terraform state files and report infrastructure drift: "
                "resources added, removed, and modified between the old and new state."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "tfstate_path_old": {
                        "type": "string",
                        "description": "Path to the older/baseline .tfstate file.",
                    },
                    "tfstate_path_new": {
                        "type": "string",
                        "description": "Path to the newer/current .tfstate file.",
                    },
                },
                "required": ["tfstate_path_old", "tfstate_path_new"],
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
    if name == "summarize_state":
        return await _summarize_state(arguments)
    if name == "compare_states":
        return await _compare_states(arguments)
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


# ---------------------------------------------------------------------------
# Tool: summarize_state
# ---------------------------------------------------------------------------

async def _summarize_state(arguments: dict[str, Any]) -> list[types.TextContent]:
    path = arguments["tfstate_path"]
    state = _load_tfstate(path)

    type_counts: dict[str, int] = {}
    module_counts: dict[str, int] = {}
    providers: set[str] = set()
    tagged = 0
    untagged = 0
    regions: set[str] = set()
    total = 0

    for address, rtype, rname, attrs in _iter_resources(state):
        total += 1

        # Count by type
        type_counts[rtype] = type_counts.get(rtype, 0) + 1

        # Count by module
        if "." in address:
            parts = address.split(".")
            if parts[0].startswith("module"):
                mod = ".".join(parts[:-2])  # e.g. module.vpc
            else:
                mod = "(root)"
        else:
            mod = "(root)"
        # Simpler: check if the resource dict had a module key
        # We need to re-derive from address — root has no "module." prefix
        if address.startswith("module."):
            # extract module path: everything before the last type.name
            idx = address.rfind(f"{rtype}.{rname}")
            mod = address[:idx].rstrip(".")
        else:
            mod = "(root)"
        module_counts[mod] = module_counts.get(mod, 0) + 1

        # Provider from type prefix
        prefix = rtype.split("_")[0]
        providers.add(prefix)

        # Tagged vs untagged
        tags = attrs.get("tags")
        if tags and isinstance(tags, dict) and len(tags) > 0:
            tagged += 1
        else:
            untagged += 1

        # Regions
        region = attrs.get("region")
        if region:
            regions.add(region)
        az = attrs.get("availability_zone")
        if az and isinstance(az, str):
            # Derive region from AZ (e.g. us-east-1a -> us-east-1)
            regions.add(az[:-1])

    if total == 0:
        return [types.TextContent(type="text", text="State file contains 0 resources.")]

    lines: list[str] = []
    lines.append(f"Total resources: {total}\n")

    # By type (sorted desc by count)
    lines.append("Resources by type:")
    for rtype, count in sorted(type_counts.items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"  {rtype}: {count}")

    # By module
    lines.append("\nResources by module:")
    for mod, count in sorted(module_counts.items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"  {mod}: {count}")

    # Providers
    lines.append(f"\nProviders: {', '.join(sorted(providers))}")

    # Tagged vs untagged
    lines.append(f"\nTagged resources: {tagged}")
    lines.append(f"Untagged resources: {untagged}")

    # Regions
    if regions:
        lines.append(f"\nRegions: {', '.join(sorted(regions))}")
    else:
        lines.append("\nRegions: none detected")

    return [types.TextContent(type="text", text="\n".join(lines))]


# ---------------------------------------------------------------------------
# Tool: compare_states
# ---------------------------------------------------------------------------

async def _compare_states(arguments: dict[str, Any]) -> list[types.TextContent]:
    path_old = arguments["tfstate_path_old"]
    path_new = arguments["tfstate_path_new"]
    state_old = _load_tfstate(path_old)
    state_new = _load_tfstate(path_new)

    # Build address -> (type, attrs) maps
    def _build_map(state: dict[str, Any]) -> dict[str, tuple[str, dict]]:
        result: dict[str, tuple[str, dict]] = {}
        for address, rtype, _, attrs in _iter_resources(state):
            result[address] = (rtype, attrs)
        return result

    old_map = _build_map(state_old)
    new_map = _build_map(state_new)

    old_addrs = set(old_map)
    new_addrs = set(new_map)

    added = sorted(new_addrs - old_addrs)
    removed = sorted(old_addrs - new_addrs)
    common = sorted(old_addrs & new_addrs)

    modified: list[tuple[str, list[str]]] = []
    unchanged = 0

    for addr in common:
        old_type, old_attrs = old_map[addr]
        new_type, new_attrs = new_map[addr]
        # Find top-level keys that differ
        all_keys = set(old_attrs) | set(new_attrs)
        changed_keys: list[str] = []
        for key in sorted(all_keys):
            old_val = old_attrs.get(key)
            new_val = new_attrs.get(key)
            if json.dumps(old_val, sort_keys=True, default=str) != json.dumps(new_val, sort_keys=True, default=str):
                changed_keys.append(key)
        if changed_keys:
            modified.append((addr, changed_keys))
        else:
            unchanged += 1

    if not added and not removed and not modified:
        return [types.TextContent(type="text", text="No differences found.")]

    lines: list[str] = []

    if added:
        lines.append(f"Added ({len(added)}):")
        for addr in added:
            rtype = new_map[addr][0]
            lines.append(f"  + {addr}  ({rtype})")

    if removed:
        if lines:
            lines.append("")
        lines.append(f"Removed ({len(removed)}):")
        for addr in removed:
            rtype = old_map[addr][0]
            lines.append(f"  - {addr}  ({rtype})")

    if modified:
        if lines:
            lines.append("")
        lines.append(f"Modified ({len(modified)}):")
        for addr, keys in modified:
            lines.append(f"  ~ {addr}  changed: {', '.join(keys)}")

    lines.append(f"\nSummary: {len(added)} added, {len(removed)} removed, {len(modified)} modified, {unchanged} unchanged")

    return [types.TextContent(type="text", text="\n".join(lines))]


def main() -> None:
    import asyncio

    async def _run():
        async with stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options())

    asyncio.run(_run())


if __name__ == "__main__":
    main()
