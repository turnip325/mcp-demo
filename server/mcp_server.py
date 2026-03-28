#!/usr/bin/env python3
"""
FortiWeb WAF Security Demo — FastMCP HTTP Server
=================================================
Exposes 5 MCP tools that demonstrate real attack vectors:
  - get_current_time : benign baseline
  - fetch_url        : SSRF vector (pass internal IP to trigger WAF)
  - read_file        : path traversal vector (../../etc/passwd)
  - query_database   : SQL injection vector (crafted WHERE clause)
  - ping_host        : OS command injection vector (shell metacharacters)

Listens on 0.0.0.0:8008, path /mcp.
TLS is terminated at FortiWeb — this server speaks plain HTTP.

Run directly:  python mcp_server.py
"""

import datetime
import sqlite3
import subprocess
from pathlib import Path

import httpx
from fastmcp import FastMCP

# ── Configuration ──────────────────────────────────────────────────────────────

# SQLite database created by setup_demo_db.py
DB_PATH = "/opt/demo/demo.db"

# Filesystem tool is scoped to /pipeline — any traversal attempt that escapes
# this root is caught here as a defense-in-depth backstop.
# FortiWeb's path traversal signature should fire before this code is reached.
PIPELINE_ROOT = Path("/pipeline").resolve()

# ── Server init ────────────────────────────────────────────────────────────────

mcp = FastMCP(
    name="fortiweb-demo",
    instructions=(
        "FortiWeb WAF security demo server. "
        "Exposes tools for demonstrating WAF attack detection and blocking."
    ),
)

# ── Tool 1: Benign baseline ────────────────────────────────────────────────────

@mcp.tool()
def get_current_time() -> str:
    """Return the current server time in UTC. Used as a benign baseline call."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return f"Current UTC time: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}"


# ── Tool 2: SSRF vector ────────────────────────────────────────────────────────

@mcp.tool()
def fetch_url(url: str) -> str:
    """
    Fetch the contents of a URL and return the response body.

    Demo attack: pass an internal IP such as http://169.254.169.254/latest/meta-data/
    or an internal RFC1918 address to demonstrate SSRF detection by FortiWeb.
    Legitimate use: fetch any public external URL.
    """
    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            response = client.get(url)
            # Cap output to avoid flooding the demo terminal
            body = response.text[:2000]
            return f"HTTP {response.status_code}\n\n{body}"
    except Exception as exc:
        return f"Request failed: {exc}"


# ── Tool 3: Path traversal vector ─────────────────────────────────────────────

@mcp.tool()
def read_file(path: str) -> str:
    """
    Read a file from the /pipeline directory and return its contents.

    Demo attack: pass ../../etc/passwd or ../../../etc/shadow to demonstrate
    path traversal detection by FortiWeb.
    Legitimate use: read files like status.txt or config.yaml under /pipeline.
    """
    # Resolve the full path relative to /pipeline and check it doesn't escape.
    # This is a defense-in-depth check — FortiWeb should block traversal payloads
    # before this function is ever called.
    requested = (PIPELINE_ROOT / path).resolve()
    if not str(requested).startswith(str(PIPELINE_ROOT)):
        raise ValueError(
            f"Access denied: '{path}' resolves outside /pipeline. "
            "FortiWeb should have intercepted this request."
        )
    if not requested.exists():
        raise FileNotFoundError(f"File not found: {requested}")
    return requested.read_text(encoding="utf-8", errors="replace")


# ── Tool 4: SQL injection vector ──────────────────────────────────────────────

@mcp.tool()
def query_database(table: str, where_clause: str = "") -> str:
    """
    Run a SELECT query against the demo SQLite database.

    Demo attack: pass a crafted where_clause such as:
      ' OR '1'='1
      1=1; DROP TABLE users; --
    to demonstrate SQL injection detection by FortiWeb.
    Legitimate use: query users or products with a plain WHERE condition.
    """
    # Restrict to known tables — this guards table name injection but
    # intentionally leaves the where_clause unsanitised for the demo.
    allowed_tables = {"users", "products"}
    if table not in allowed_tables:
        raise ValueError(
            f"Table '{table}' is not allowed. Choose from: {sorted(allowed_tables)}"
        )

    sql = f"SELECT * FROM {table}"
    if where_clause:
        sql += f" WHERE {where_clause}"

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.execute(sql)
        rows = cursor.fetchall()
        col_names = [desc[0] for desc in cursor.description]
        conn.close()
    except sqlite3.Error as exc:
        return f"Database error: {exc}"

    if not rows:
        return "Query returned no rows."

    # Format as a simple text table
    lines = [" | ".join(col_names)]
    lines.append("-" * len(lines[0]))
    lines += [" | ".join(str(v) for v in row) for row in rows]
    return "\n".join(lines)


# ── Tool 5: OS command injection vector ───────────────────────────────────────

@mcp.tool()
def ping_host(host: str) -> str:
    """
    Ping a host and return the output.

    Demo attack: pass a host containing shell metacharacters, e.g.:
      google.com; cat /etc/passwd
      google.com `id`
      google.com && whoami
    to demonstrate OS command injection detection by FortiWeb.
    Legitimate use: ping a hostname or IP address to check reachability.

    WARNING: shell=True is intentional here — this tool is deliberately
    vulnerable to command injection so FortiWeb has something to block.
    Do NOT use this pattern in production code.
    """
    cmd = f"ping -c 4 {host}"
    try:
        result = subprocess.run(
            cmd,
            shell=True,           # intentionally unsafe — for demo purposes only
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = result.stdout or result.stderr
        return output[:2000]      # cap output length
    except subprocess.TimeoutExpired:
        return "Ping timed out after 15 seconds."
    except Exception as exc:
        return f"Error running ping: {exc}"


# ── Entrypoint ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # streamable-http is FastMCP 2.x's native HTTP/SSE transport.
    # The path /mcp matches the FortiWeb content routing rule.
    #
    # CORS is enabled for the console origin so the browser-based demo console
    # can make cross-origin requests. Set CONSOLE_ORIGIN to match wherever you
    # host the console (e.g. https://console.example.com).
    # Mcp-Session-Id must be in both allow_headers (so the browser can send it)
    # and expose_headers (so the browser can read it from the initialize response).
    import os
    from starlette.middleware import Middleware
    from starlette.middleware.cors import CORSMiddleware

    console_origin = os.environ.get("CONSOLE_ORIGIN", "https://console.example.com")

    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=8008,
        path="/mcp",
        middleware=[
            Middleware(
                CORSMiddleware,
                allow_origins=[console_origin],
                allow_methods=["POST", "OPTIONS"],
                allow_headers=["Content-Type", "Accept", "Mcp-Session-Id"],
                expose_headers=["Mcp-Session-Id"],
            )
        ],
    )
