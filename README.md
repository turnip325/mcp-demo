# FortiWeb WAF Demo — MCP Attack Console

A repeatable lab demonstrating FortiWeb WAF detecting and blocking attack payloads delivered through [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) tool calls.

Inspired by and forked from [benoitbMTL/mcp-demo](https://github.com/benoitbMTL/mcp-demo).

---

## What This Is

An MCP server exposes five intentionally vulnerable tools. A browser-based console sends both legitimate calls and crafted attack payloads through FortiWeb. The WAF inspects the JSON request bodies and blocks attack payloads before they reach the server.

This demonstrates that FortiWeb can protect AI/LLM tool-use workflows — not just traditional web traffic.

---

## Architecture

```
Test Client (browser console)
    │  HTTP POST /api/call  (localhost:8000)
    ▼
Console Proxy (console/server.py)
    │  HTTPS POST /mcp
    ▼
FortiWeb WAF  ← inspects JSON body, blocks attack payloads
    │  HTTP POST /mcp  (port 8008)
    ▼
MCP Demo Server (server/mcp_server.py)
    │
    ├── get_current_time  — benign baseline
    ├── fetch_url         — SSRF vector
    ├── read_file         — path traversal vector  (/pipeline scope)
    ├── query_database    — SQL injection vector   (SQLite)
    └── ping_host         — OS command injection   (shell=True intentionally)
```

TLS is terminated at FortiWeb. The MCP server speaks plain HTTP internally.

---

## Attack Scenarios

| # | Category | Tool | Payload |
|---|---|---|---|
| 1 | Path Traversal | `read_file` | `../../etc/passwd` |
| 2 | Path Traversal | `read_file` | `../../../etc/shadow` |
| 3 | SQL Injection | `query_database` | `1=1 OR '1'='1'` |
| 4 | Command Injection | `ping_host` | `google.com; cat /etc/passwd` |
| 5 | Command Injection | `ping_host` | `google.com \`id\`` |

FortiWeb should return HTTP 403 or a block page for all five. Legitimate calls (time, safe file reads, normal queries, public pings) must pass through.

---

## Setup — MCP Demo Server

**Prerequisites:** Linux host, Python 3.10+, internet access for pip.

```bash
# 1. Copy files to the server
scp -r server   user@YOUR_MCP_SERVER_IP:/tmp/mcp-demo-deploy/server
scp -r systemd  user@YOUR_MCP_SERVER_IP:/tmp/mcp-demo-deploy/systemd

# 2. Run the provisioning script on the server (as root)
scp scripts/provision.sh user@YOUR_MCP_SERVER_IP:/tmp/provision.sh
ssh user@YOUR_MCP_SERVER_IP "sudo bash /tmp/provision.sh"
```

`provision.sh` will:
- Install Python 3, create a virtualenv, install `fastmcp` and `httpx`
- Create a `mcpdemo` service user
- Seed `/pipeline/` with `status.txt` and `config.yaml` (legitimate read targets)
- Create the demo SQLite database (`users` and `products` tables)
- Install and start the `mcp-demo` systemd service on port 8008

**CORS:** Set the `CONSOLE_ORIGIN` environment variable on the server if you host the console at a domain (e.g. `CONSOLE_ORIGIN=https://console.example.com`). For local-only use the default is fine.

---

## Setup — Test Console

The console is a local Python HTTP server that serves the browser UI and proxies MCP calls.

```bash
# Set your WAF external endpoint
export MCP_ENDPOINT=https://mcp.example.com/mcp

# Start the console
bash scripts/run_console.sh
# then open http://localhost:8000
```

---

## FortiWeb Configuration

The MCP server must sit behind a FortiWeb reverse proxy. FortiWeb configuration required:

1. **Reverse proxy policy** routing HTTPS traffic to `YOUR_MCP_SERVER_IP:8008`
2. **Web Protection Profile** with these signature categories **set to Block** (not Alert):
   - Path Traversal
   - SQL Injection
   - OS Command Injection
3. **JSON Body Inspection enabled** — this is critical. Without it, FortiWeb does not inspect payloads inside JSON request bodies, and attacks pass through.
   - *FortiWeb GUI → Web Protection → Protocol Constraints → JSON Validation → Enable*

> **SSL certificate note:** If connecting a Claude Desktop client via HTTPS, the full certificate chain (including intermediate CA) must be present in the FortiWeb certificate object. Claude clients — unlike browsers — reject missing intermediates.

---

## Testing

```bash
# Verify legitimate calls pass through (Phase A: direct, Phase B: via WAF)
export MCP_SERVER_IP=YOUR_MCP_SERVER_IP
export MCP_ENDPOINT=https://mcp.example.com/mcp
bash scripts/test_baseline.sh

# Send attack payloads — all should be blocked
bash scripts/demo_attacks.sh
```

After running `demo_attacks.sh`, check the FortiWeb attack log:
*Log & Report → Attack Log → filter last 30 minutes*

---

## File Layout

```
server/
  mcp_server.py      — FastMCP HTTP server (the vulnerable demo tools)
  setup_demo_db.py   — Seeds the SQLite demo database
  requirements.txt   — Python dependencies (fastmcp, httpx)

console/
  server.py          — Local proxy server (serves UI, proxies MCP calls)
  static/index.html  — Browser-based demo console UI

scripts/
  provision.sh       — Bootstrap a fresh Linux server
  test_baseline.sh   — Verify legitimate calls pass through the WAF
  demo_attacks.sh    — Send attack payloads through the WAF
  run_console.sh     — Start the local console

systemd/
  mcp-demo.service   — systemd unit for the MCP server
```

---

## Security Note

The tools in `mcp_server.py` are **intentionally vulnerable** to demonstrate WAF detection. `ping_host` uses `shell=True`; `query_database` does not sanitise the `where_clause`; `read_file` accepts any path. Do not deploy this server without a WAF in front of it, and do not use these patterns in production code.
