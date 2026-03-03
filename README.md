# mcp-tfstate-reader

[![PyPI Version](https://img.shields.io/pypi/v/mcp-tfstate-reader?color=blue&style=flat-square)](https://pypi.org/project/mcp-tfstate-reader/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/mcp-tfstate-reader?color=success&style=flat-square)](https://pypi.org/project/mcp-tfstate-reader/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg?style=flat-square)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

A local **Model Context Protocol (MCP) server** that parses Terraform `.tfstate` files and lets AI agents audit enterprise infrastructure for security misconfigurations — without requiring direct cloud credentials.

---

## Why?

Terraform state files are the single source of truth for what's actually deployed in your cloud. Security teams need to audit them regularly, but the traditional workflow is manual: run CLI tools, parse terminal output, repeat.

**mcp-tfstate-reader** gives AI agents (like Claude) structured, read-only access to your Terraform state. Instead of copying JSON into a chat window, you ask a question and the agent calls the right tool automatically.

---

## Features

| Tool                  | Description                                                                       |
| --------------------- | --------------------------------------------------------------------------------- |
| `list_resources`      | Parse a `.tfstate` file and list every managed resource with its address and type |
| `audit_security`      | Scan for common misconfigurations (see below)                                     |
| `get_resource_detail` | Dump the full attributes of a specific resource by address                        |

### Security checks in `audit_security`

- **S3** — buckets without server-side encryption
- **Security Groups** — ingress rules open to `0.0.0.0/0` on sensitive ports: 22 (SSH), 3389 (RDP), 5432 (PostgreSQL)
- **IAM** — policies with wildcard `*` actions (full admin access)
- **RDS** — instances without `storage_encrypted = true`
- **EC2** — instances with `associate_public_ip_address = true`
- **CloudWatch** — log groups without a retention policy

---

## Quick Start

### 1. Install

```bash
pip install mcp-tfstate-reader
```

### 2. Configure Claude Desktop

Add this to your Claude Desktop MCP configuration file:

| OS      | Path                                                              |
| ------- | ----------------------------------------------------------------- |
| macOS   | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json`                     |

**Recommended — with `uvx` (no install required):**

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

> **Note:** Claude Desktop may not inherit your terminal's `$PATH`. If the server fails to connect, use the absolute path to `uvx` (find it with `which uvx` in your terminal):
>
> ```json
> {
>   "mcpServers": {
>     "tfstate-reader": {
>       "command": "/full/path/to/uvx",
>       "args": ["mcp-tfstate-reader"]
>     }
>   }
> }
> ```

**Alternative — installed via pip:**

```json
{
  "mcpServers": {
    "tfstate-reader": {
      "command": "mcp-tfstate-reader"
    }
  }
}
```

**Alternative — from source (virtualenv):**

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

### 3. Restart Claude Desktop

Fully quit (`Cmd+Q` on macOS) and reopen. Look for the tools icon to confirm the server is connected.

### 4. Ask a question

> "Audit the Terraform state file at `/path/to/terraform.tfstate` for security issues."

---

## Example interaction

Claude autonomously chains the tools — listing resources first, running the audit, then drilling into critical findings:

```
Found 7 finding(s):

[CRITICAL] aws_iam_policy.admin: IAM policy contains a wildcard (*) action — grants unrestricted permissions.
[HIGH] aws_s3_bucket.assets: S3 bucket has no server-side encryption configuration.
[HIGH] aws_security_group.bastion: Security group allows 0.0.0.0/0 ingress on port 22.
[HIGH] aws_security_group.rdp_open: Security group allows 0.0.0.0/0 ingress on port 3389.
[HIGH] aws_db_instance.prod: RDS instance storage is not encrypted.
[MEDIUM] aws_instance.web: EC2 instance has a public IP address assigned.
[MEDIUM] aws_cloudwatch_log_group.app: CloudWatch log group has no retention policy (logs kept indefinitely).
```

---

## Troubleshooting

**Server not appearing in Claude Desktop**

1. Ensure Claude Desktop is fully restarted (quit with `Cmd+Q`, not just close the window).
2. Check your config JSON is valid — a trailing comma or typo will silently break it.
3. Use absolute paths if `uvx` or `mcp-tfstate-reader` aren't found.

**"File not found" errors**

The tool reads files from your local filesystem. Use the full absolute path (e.g. `/Users/you/infra/terraform.tfstate`), not relative paths.

**This is Claude Desktop only**

MCP servers work with the Claude Desktop app, not claude.ai in your browser. The web interface does not have access to local MCP servers or your filesystem.

---

## Development

```bash
# Clone and set up
git clone https://github.com/berkayyildirim/mcp-tfstate-reader.git
cd mcp-tfstate-reader
make setup

# Run tests
make test

# Build distribution
make build

# Run the server locally (stdio)
make start

# Clean everything
make clean
```

---

## License

MIT © Berkay Yildirim
