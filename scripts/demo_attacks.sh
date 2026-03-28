#!/usr/bin/env bash
# demo_attacks.sh — Send attack payloads through FortiWeb to the MCP server.
# ===========================================================================
# Each request targets a specific WAF signature category. FortiWeb should
# BLOCK all of them — the payload never reaches the server.
#
# NOTE: Attack requests do NOT need a valid session. FortiWeb inspects and
# blocks the request body before it reaches the server's session layer.
# Each attack is sent with a bogus session ID to keep curl simple.
#
# Run this during the live demo after confirming baseline tests pass.
# After the script, show the FortiWeb attack log:
#   Log & Report → Attack Log → filter last 30 minutes
#
# Usage: bash scripts/demo_attacks.sh
# ===========================================================================
EXTERNAL_URL="${MCP_ENDPOINT:-https://mcp.example.com/mcp}"
BLOCKED=0
NOT_BLOCKED=0

# Sends an attack payload, prints result, tracks block/pass.
# Args: <attack_name> <signature_category> <tool_name> <arguments_json>
run_attack() {
    local name="$1"
    local category="$2"
    local tool="$3"
    local args="$4"

    local payload
    payload=$(printf '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"%s","arguments":%s}}' "$tool" "$args")

    echo "┌─────────────────────────────────────────────────────────────"
    echo "│ Attack:    $name"
    echo "│ Category:  $category"
    echo "│ Payload:   $(echo "$args" | tr -d '\n')"

    http_code=$(curl -sk --max-time 10 -o /tmp/mcp_attack.txt -w "%{http_code}" \
        -X POST "$EXTERNAL_URL" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -H "Mcp-Session-Id: attack-test-session" \
        -d "$payload")

    body=$(cat /tmp/mcp_attack.txt)
    preview=$(echo "$body" | head -c 200 | tr '\n' ' ')

    echo "│ HTTP:      $http_code"
    echo "│ Response:  $preview"

    if [[ "$http_code" == "403" || "$http_code" == "400" ]]; then
        echo "│ Result:    BLOCKED by FortiWeb ✓"
        ((BLOCKED++))
    elif echo "$body" | grep -qi "fortiweb\|blocked\|access denied\|security violation"; then
        echo "│ Result:    BLOCKED — FortiWeb block page (HTTP $http_code) ✓"
        ((BLOCKED++))
    else
        echo "│ Result:    NOT BLOCKED (HTTP $http_code) ✗"
        echo "│            → Check FortiWeb: signature action set to Block? JSON inspection enabled?"
        ((NOT_BLOCKED++))
    fi

    echo "└─────────────────────────────────────────────────────────────"
    echo ""
}

# ── Header ────────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  FortiWeb WAF Demo — Attack Payloads"
echo "  Target: $EXTERNAL_URL"
echo "  Expected: ALL attacks BLOCKED (403 or FortiWeb block page)"
echo "============================================================"
echo ""

# ── Path Traversal ────────────────────────────────────────────────────────────
echo "=== Category: Path Traversal ==="
echo ""

run_attack \
    "Classic dot-dot-slash traversal" \
    "Path Traversal" \
    "read_file" \
    '{"path":"../../etc/passwd"}'

run_attack \
    "Deep traversal to shadow file" \
    "Path Traversal" \
    "read_file" \
    '{"path":"../../../etc/shadow"}'

# ── SQL Injection ─────────────────────────────────────────────────────────────
echo "=== Category: SQL Injection ==="
echo ""

run_attack \
    "OR 1=1 tautology" \
    "SQL Injection" \
    "query_database" \
    '{"table":"users","where_clause":"1=1 OR '\''1'\''='\''1'\''"}'

# ── OS Command Injection ──────────────────────────────────────────────────────
echo "=== Category: OS Command Injection ==="
echo ""

run_attack \
    "Semicolon shell separator" \
    "OS Command Injection" \
    "ping_host" \
    '{"host":"google.com; cat /etc/passwd"}'

run_attack \
    "Backtick subshell execution" \
    "OS Command Injection" \
    "ping_host" \
    '{"host":"google.com `id`"}'

# ── Summary ───────────────────────────────────────────────────────────────────
TOTAL=$((BLOCKED + NOT_BLOCKED))
echo "============================================================"
echo "  Attack demo complete."
echo "  Blocked: $BLOCKED / $TOTAL"
if [[ "$NOT_BLOCKED" -gt 0 ]]; then
    echo ""
    echo "  WARNING: $NOT_BLOCKED attack(s) not blocked. Check:"
    echo "    1. FortiWeb GUI → Web Protection → Signatures"
    echo "       Ensure each category action is 'Block' (not 'Alert')"
    echo "    2. FortiWeb GUI → Web Protection → Protocol Constraints"
    echo "       → JSON Validation → must be ENABLED"
    echo "       (Without this, payloads in JSON bodies are not inspected)"
fi
echo ""
echo "  Next: FortiWeb GUI → Log & Report → Attack Log"
echo "        Filter last 30 minutes — should show $BLOCKED blocked events."
echo "============================================================"
echo ""
