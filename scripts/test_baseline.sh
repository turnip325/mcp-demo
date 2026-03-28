#!/usr/bin/env bash
# test_baseline.sh — Verify that legitimate MCP tool calls work correctly.
# ===========================================================================
# Tests clean (non-attack) requests in two phases:
#   Phase A: Direct to YOUR_MCP_SERVER_IP:8008 (bypasses FortiWeb — server health check)
#   Phase B: Via the WAF external endpoint (through FortiWeb)
#
# All tests should return HTTP 200 with valid JSON content.
# If Phase A passes but Phase B fails, the issue is in FortiWeb routing or
# an overly aggressive WAF rule blocking legitimate JSON requests.
#
# Set MCP_SERVER_IP and MCP_ENDPOINT before running, or edit the defaults below.
#
# Usage: bash scripts/test_baseline.sh
# ===========================================================================
INTERNAL_URL="http://${MCP_SERVER_IP:-YOUR_MCP_SERVER_IP}:8008/mcp"
EXTERNAL_URL="${MCP_ENDPOINT:-https://mcp.example.com/mcp}"
PASS=0
FAIL=0

# ── MCP session management ────────────────────────────────────────────────────
# The MCP streamable-http transport requires an initialize handshake before
# tool calls. This function creates a session and returns the session ID.
get_session_id() {
    local url="$1"
    local session_id

    # Step 1: initialize — returns Mcp-Session-Id header
    session_id=$(curl -si --max-time 10 -X POST "$url" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -d '{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-baseline", "version": "1.0"}
            }
        }' | grep -i "mcp-session-id" | awk '{print $2}' | tr -d '\r')

    if [[ -z "$session_id" ]]; then
        echo "ERROR: Could not obtain session ID from $url" >&2
        return 1
    fi

    # Step 2: send initialized notification (no response expected)
    curl -s --max-time 5 -X POST "$url" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -H "Mcp-Session-Id: $session_id" \
        -d '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' \
        > /dev/null || true

    echo "$session_id"
}

# Sends a tool call, checks HTTP status and response body for expected content.
# Args: <test_name> <url> <session_id> <tool_name> <arguments_json> <expected_string>
run_test() {
    local name="$1"
    local url="$2"
    local session="$3"
    local tool="$4"
    local args="$5"
    local expected="$6"

    printf "  %-52s " "$name"

    rm -f /tmp/mcp_response.txt
    http_code=$(curl -sk --max-time 20 -o /tmp/mcp_response.txt -w "%{http_code}" \
        -X POST "$url" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -H "Mcp-Session-Id: $session" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"tools/call\",\"params\":{\"name\":\"$tool\",\"arguments\":$args}}")

    body=$(cat /tmp/mcp_response.txt)

    if [[ "$http_code" != "200" ]]; then
        echo "FAIL (HTTP $http_code)"
        echo "      Response: $(echo "$body" | head -c 200)"
        ((FAIL++))
    elif ! echo "$body" | grep -q "$expected"; then
        echo "FAIL (missing '$expected' in response)"
        echo "      Response: $(echo "$body" | head -c 300)"
        ((FAIL++))
    else
        echo "PASS (HTTP $http_code)"
        ((PASS++))
    fi
}

# ── Header ────────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  FortiWeb WAF Demo — Baseline (Legitimate) Tool Calls"
echo "============================================================"
echo ""

# ── Phase A: Internal (bypasses FortiWeb) ─────────────────────────────────────
echo "Phase A — Direct to server ($INTERNAL_URL) [bypasses WAF]"
echo "  (FortiWeb bypassed — tests server health only)"
echo ""

SESSION_A=$(get_session_id "$INTERNAL_URL")
echo "  Session: $SESSION_A"
echo ""

run_test "get_current_time"                     "$INTERNAL_URL" "$SESSION_A" "get_current_time"  '{}'                                                    "UTC"
run_test "read_file status.txt"                 "$INTERNAL_URL" "$SESSION_A" "read_file"         '{"path":"status.txt"}'                                 "Pipeline"
run_test "read_file config.yaml"                "$INTERNAL_URL" "$SESSION_A" "read_file"         '{"path":"config.yaml"}'                                "pipeline"
run_test "query_database users"                 "$INTERNAL_URL" "$SESSION_A" "query_database"    '{"table":"users"}'                                     "alice"
run_test "query_database products"              "$INTERNAL_URL" "$SESSION_A" "query_database"    '{"table":"products"}'                                  "FortiWeb"
run_test "query_database products (price>1000)" "$INTERNAL_URL" "$SESSION_A" "query_database"    '{"table":"products","where_clause":"price > 1000"}'    "FortiWeb"
run_test "fetch_url (safe external URL)"        "$INTERNAL_URL" "$SESSION_A" "fetch_url"         '{"url":"https://httpbin.org/get"}'                     "origin"
run_test "ping_host (legitimate IP)"            "$INTERNAL_URL" "$SESSION_A" "ping_host"         '{"host":"8.8.8.8"}'                                    "bytes"

PHASE_A_PASS=$PASS
PHASE_A_FAIL=$FAIL
echo ""
echo "  Phase A: $PHASE_A_PASS passed, $PHASE_A_FAIL failed"
echo ""

# ── Phase B: External (through FortiWeb) ──────────────────────────────────────
echo "Phase B — Via FortiWeb ($EXTERNAL_URL)"
echo "  (Full path: client → FortiWeb WAF → server)"
echo ""

PASS=0
FAIL=0

SESSION_B=$(get_session_id "$EXTERNAL_URL")
echo "  Session: $SESSION_B"
echo ""

run_test "get_current_time"                     "$EXTERNAL_URL" "$SESSION_B" "get_current_time"  '{}'                                                    "UTC"
run_test "read_file status.txt"                 "$EXTERNAL_URL" "$SESSION_B" "read_file"         '{"path":"status.txt"}'                                 "Pipeline"
run_test "query_database users"                 "$EXTERNAL_URL" "$SESSION_B" "query_database"    '{"table":"users"}'                                     "alice"
run_test "query_database products (price>1000)" "$EXTERNAL_URL" "$SESSION_B" "query_database"    '{"table":"products","where_clause":"price > 1000"}'    "FortiWeb"
run_test "fetch_url (safe external URL)"        "$EXTERNAL_URL" "$SESSION_B" "fetch_url"         '{"url":"https://httpbin.org/get"}'                     "origin"
run_test "ping_host (legitimate IP)"            "$EXTERNAL_URL" "$SESSION_B" "ping_host"         '{"host":"8.8.8.8"}'                                    "bytes"

PHASE_B_PASS=$PASS
PHASE_B_FAIL=$FAIL
echo ""
echo "  Phase B: $PHASE_B_PASS passed, $PHASE_B_FAIL failed"
echo ""

# ── Summary ───────────────────────────────────────────────────────────────────
echo "============================================================"
TOTAL_FAIL=$((PHASE_A_FAIL + PHASE_B_FAIL))
if [[ "$TOTAL_FAIL" -eq 0 ]]; then
    echo "  ALL TESTS PASSED — server healthy, FortiWeb routing correctly."
    echo "  Ready to run: bash scripts/demo_attacks.sh"
else
    echo "  $TOTAL_FAIL test(s) FAILED."
    if [[ "$PHASE_A_FAIL" -gt 0 ]]; then
        echo "  Phase A failures → MCP server issue."
        echo "    Check: ssh mcpdemo 'sudo journalctl -u mcp-demo -n 50'"
    fi
    if [[ "$PHASE_B_FAIL" -gt 0 && "$PHASE_A_FAIL" -eq 0 ]]; then
        echo "  Phase A OK, Phase B failures → FortiWeb issue."
        echo "    Check: pool IP, route-mcp status, JSON body inspection setting."
    fi
fi
echo "============================================================"
echo ""
