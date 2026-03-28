#!/usr/bin/env python3
"""
FortiWeb WAF Demo — Local MCP Console Server
=============================================
A lightweight local HTTP server that:
  - Serves the browser-based demo UI (console/static/index.html)
  - Manages the MCP session lifecycle (initialize handshake)
  - Proxies tool calls server-side to the configured MCP endpoint (MCP_ENDPOINT)

Why proxy server-side? The browser cannot make cross-origin requests to the
FortiWeb endpoint directly (CORS). Running the proxy here means all traffic
to FortiWeb originates from the WSL machine as expected, and FortiWeb attack
log entries appear just as they would from demo_attacks.sh.

Usage:
  python3 console/server.py
  # then open http://localhost:8000
"""

import http.server
import json
import os
import ssl
import threading
import urllib.error
import urllib.request

# Set MCP_ENDPOINT to the full URL of your MCP server (through the WAF).
# Example: https://mcp.example.com/mcp
REMOTE_URL = os.environ.get("MCP_ENDPOINT", "https://mcp.example.com/mcp")
LISTEN_PORT = 8000
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

# In-memory session store — one session shared across all browser requests.
# Re-initialised on demand or via the /api/session endpoint.
_session_lock = threading.Lock()
_session_id: str | None = None


def _mcp_post(payload: dict, session_id: str | None = None, timeout: int = 20) -> tuple[int, str, dict]:
    """
    POST a JSON-RPC payload to the remote MCP endpoint.

    Returns (http_status_code, response_body_text, response_headers_dict).
    On network error, returns (0, error_message, {}).
    """
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        REMOTE_URL,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
    )
    if session_id:
        req.add_header("Mcp-Session-Id", session_id)

    # urllib validates SSL by default; no need to disable verification
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            headers = dict(resp.getheaders())
            body_text = resp.read().decode("utf-8", errors="replace")
            return status, body_text, headers
    except urllib.error.HTTPError as e:
        # HTTPError still carries a readable body (e.g. FortiWeb block page)
        body_text = e.read().decode("utf-8", errors="replace")
        headers = dict(e.headers)
        return e.code, body_text, headers
    except Exception as exc:
        return 0, str(exc), {}


def _initialize_session() -> str:
    """
    Run the MCP initialize handshake and return the new session ID.
    Raises RuntimeError if the handshake fails.
    """
    init_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "fortiweb-demo-console", "version": "1.0"},
        },
    }
    status, body, headers = _mcp_post(init_payload, timeout=15)

    # Session ID comes back in the response header
    session_id = headers.get("Mcp-Session-Id") or headers.get("mcp-session-id")
    if not session_id:
        raise RuntimeError(
            f"No Mcp-Session-Id in initialize response (HTTP {status}): {body[:200]}"
        )

    # Send notifications/initialized — server expects this before tool calls
    notif_payload = {
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {},
    }
    _mcp_post(notif_payload, session_id=session_id, timeout=10)

    return session_id


def _get_or_create_session() -> str:
    """Return the cached session ID, creating a new session if needed."""
    global _session_id
    with _session_lock:
        if not _session_id:
            _session_id = _initialize_session()
        return _session_id


def _clear_session():
    global _session_id
    with _session_lock:
        _session_id = None


class ConsoleHandler(http.server.BaseHTTPRequestHandler):
    """Handles browser requests from the demo console UI."""

    def log_message(self, fmt, *args):
        # Suppress the default per-request stdout noise during the demo
        pass

    def _send_json(self, status: int, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: str):
        try:
            with open(path, "rb") as f:
                content = f.read()
        except FileNotFoundError:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send_file(os.path.join(STATIC_DIR, "index.html"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"

        if self.path == "/api/session":
            self._handle_session()
        elif self.path == "/api/call":
            try:
                body = json.loads(raw)
            except json.JSONDecodeError:
                self._send_json(400, {"error": "Invalid JSON"})
                return
            self._handle_call(body)
        else:
            self.send_response(404)
            self.end_headers()

    def _handle_session(self):
        """
        POST /api/session — Force a fresh MCP session.
        Clears any cached session and runs a new initialize handshake.
        """
        _clear_session()
        try:
            sid = _get_or_create_session()
            self._send_json(200, {"session_id": sid})
        except Exception as exc:
            self._send_json(500, {"error": str(exc)})

    def _handle_call(self, body: dict):
        """
        POST /api/call — Proxy a tool call to the remote MCP endpoint.

        Expected request body:
          {"tool": "tool_name", "arguments": {...}}

        Returns:
          {"http_code": NNN, "body": "...", "blocked": true/false}
        """
        tool = body.get("tool", "")
        arguments = body.get("arguments", {})

        # Auto-create session if needed; attack payloads will still be blocked
        # by FortiWeb before the server checks the session — but using a real
        # session keeps legitimate calls working correctly.
        try:
            sid = _get_or_create_session()
        except Exception as exc:
            self._send_json(500, {"error": f"Session init failed: {exc}"})
            return

        call_payload = {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        }

        http_code, resp_body, _ = _mcp_post(call_payload, session_id=sid, timeout=20)

        # Determine whether FortiWeb blocked the request.
        # Block indicators: HTTP 403/500 with FortiWeb block page content.
        blocked = http_code in (403, 500) or any(
            kw in resp_body.lower()
            for kw in ("web page blocked", "access denied", "security violation", "fortiweb")
        )

        self._send_json(200, {
            "http_code": http_code,
            "body": resp_body,
            "blocked": blocked,
        })


def main():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", LISTEN_PORT), ConsoleHandler)
    print(f"FortiWeb WAF Demo Console")
    print(f"  Serving at:  http://localhost:{LISTEN_PORT}")
    print(f"  Proxying to: {REMOTE_URL}")
    print(f"  Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
