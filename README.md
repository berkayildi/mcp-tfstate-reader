# mcp-tfstate-reader

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![MCP](https://img.shields.io/badge/MCP-1.0-green.svg)](https://modelcontextprotocol.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A local **Model Context Protocol (MCP) server** that parses Terraform `.tfstate` files and lets AI agents audit enterprise infrastructure for security misconfigurations — without requiring direct cloud credentials.

---

## Features

| Tool | Description |
|------|-------------|
| `list_resources` | Parse a `.tfstate` file and list every managed resource with its address and type |
| `audit_security` | Scan for common misconfigurations (see below) |
| `get_resource_detail` | Dump the full attributes of a specific resource by address |

### Security checks in `audit_security`

- **S3** — buckets without server-side encryption
- **Security Groups** — ingress rules open to `0.0.0.0/0` on sensitive ports: 22 (SSH), 3389 (RDP), 5432 (PostgreSQL)
- **IAM** — policies with wildcard `*` actions (full admin access)
- **RDS** — instances without `storage_encrypted = true`
- **EC2** — instances with `associate_public_ip_address = true`
- **CloudWatch** — log groups without a retention policy

---

## Requirements

- Python 3.10+
- [`mcp`](https://pypi.org/project/mcp/) SDK

---

## Installation

```bash
git clone https://github.com/berkay-yildirim/mcp-tfstate-reader.git
cd mcp-tfstate-reader
make setup
```

Or install directly:

```bash
pip install mcp-tfstate-reader
```

---

## Usage

### Run the server

```bash
make start
# or
python -m mcp_tfstate_reader.server
```

The server communicates over **stdio** (standard input/output), which is the default MCP transport for local tools.

### Use with a tfstate file

Point any of the three tools at a local `.tfstate` file path:

```json
{
  "tfstate_path": "/path/to/terraform.tfstate"
}
```

---

## Claude Desktop integration

Add the following to your Claude Desktop MCP configuration file:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

### Option A — installed via pip

```json
{
  "mcpServers": {
    "tfstate-reader": {
      "command": "mcp-tfstate-reader"
    }
  }
}
```

### Option B — from source (virtualenv)

```json
{
  "mcpServers": {
    "tfstate-reader": {
      "command": "/absolute/path/to/mcp-tfstate-reader/.venv/bin/python",
      "args": ["-m", "mcp_tfstate_reader.server"]
    }
  }
}
```

### Option C — with `uvx` (no install required)

```json
{
  "mcpServers": {
    "tfstate-reader": {
      "command": "uvx",
      "args": ["mcp-tfstate-reader"]
    }
  }
}
```

---

## Development

```bash
# Install with dev dependencies
make setup

# Run tests
make test

# Build distribution
make build

# Clean everything
make clean
```

---

## Example interaction

Once connected to Claude Desktop, you can ask:

> "Audit `/home/user/infra/prod/terraform.tfstate` for security issues."

Claude will call `audit_security` and return a structured list of findings like:

```
Found 4 finding(s):

[HIGH] aws_s3_bucket.assets: S3 bucket has no server-side encryption configuration.
[HIGH] aws_security_group.bastion: Security group allows 0.0.0.0/0 ingress on port 22.
[CRITICAL] aws_iam_policy.admin: IAM policy contains a wildcard (*) action — grants unrestricted permissions.
[HIGH] aws_db_instance.prod: RDS instance storage is not encrypted.
```

---

## License

MIT © Berkay Yildirim
