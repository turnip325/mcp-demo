#!/usr/bin/env bash
# run_console.sh — Start the FortiWeb WAF demo console locally.
# ===========================================================================
# Launches a lightweight Python HTTP server that:
#   - Serves the browser UI at http://localhost:8000
#   - Proxies MCP tool calls to the endpoint set in MCP_ENDPOINT
#
# The proxy runs server-side so the browser avoids CORS restrictions and all
# traffic to FortiWeb originates from this machine (appears in attack logs).
#
# Usage:
#   bash scripts/run_console.sh
#   # then open http://localhost:8000 in your browser
# ===========================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo ""
echo "============================================================"
echo "  FortiWeb WAF Demo — MCP Attack Console"
echo "============================================================"
echo ""
echo "  Open this URL in your browser:"
echo "    http://localhost:8000"
echo ""
echo "  Press Ctrl+C to stop."
echo "============================================================"
echo ""

python3 "$PROJECT_DIR/console/server.py"
