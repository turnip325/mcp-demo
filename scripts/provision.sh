#!/usr/bin/env bash
# provision.sh — Bootstrap the demo server for the FortiWeb WAF demo lab
# ===========================================================================
# Run as root (or with sudo) on your MCP demo server.
# Idempotent — safe to re-run without breaking an existing install.
#
# From your workstation:
#   scp scripts/provision.sh user@YOUR_MCP_SERVER_IP:/tmp/provision.sh
#   ssh user@YOUR_MCP_SERVER_IP "sudo bash /tmp/provision.sh"
# ===========================================================================
set -euo pipefail

DEMO_DIR="/opt/demo"
PIPELINE_DIR="/pipeline"
SERVICE_USER="mcpdemo"
VENV="$DEMO_DIR/venv"
SERVICE_FILE="/etc/systemd/system/mcp-demo.service"
# Files are scp'd here before this script runs
STAGING="/tmp/mcp-demo-deploy"

echo "================================================================"
echo "  FortiWeb WAF Demo — Server Provisioning"
echo "  Host: $(hostname) / $(hostname -I | awk '{print $1}')"
echo "================================================================"
echo ""

# ── [1/8] System packages ─────────────────────────────────────────────────────
echo "--- [1/8] Updating system packages ---"
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
apt-get install -y python3 python3-pip python3-venv curl net-tools iputils-ping
echo "Done."
echo ""

# ── [2/8] Service user ────────────────────────────────────────────────────────
echo "--- [2/8] Creating service user '$SERVICE_USER' ---"
if id "$SERVICE_USER" &>/dev/null; then
    echo "User '$SERVICE_USER' already exists — skipping."
else
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    echo "User '$SERVICE_USER' created."
fi
echo ""

# ── [3/8] Directories and demo file content ───────────────────────────────────
echo "--- [3/8] Creating directories and seeding /pipeline ---"
mkdir -p "$DEMO_DIR"
mkdir -p "$PIPELINE_DIR"

# Seed /pipeline with plausible files the read_file tool can serve legitimately.
# These give the demo audience something real to look at before the attack payload.
cat > "$PIPELINE_DIR/status.txt" <<'EOF'
Pipeline Status Report
======================
Build:   SUCCESS
Tests:   47/47 passed
Deploy:  PENDING approval
Env:     production
Last run: 2026-03-27 08:00 UTC

Recent changes:
  - Updated auth middleware to JWT v2
  - Bumped base image to python:3.12-slim
  - Fixed race condition in task scheduler
EOF

cat > "$PIPELINE_DIR/config.yaml" <<'EOF'
pipeline:
  name: demo-app
  version: "1.4.2"
  environment: production

database:
  host: db.internal
  port: 5432
  name: appdb
  pool_size: 10

logging:
  level: INFO
  destination: stdout
  format: json
EOF

echo "Done. Files in $PIPELINE_DIR:"
ls -la "$PIPELINE_DIR"
echo ""

# ── [4/8] Python venv and dependencies ────────────────────────────────────────
echo "--- [4/8] Setting up Python venv at $VENV ---"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip --quiet
"$VENV/bin/pip" install --quiet fastmcp httpx

echo "FastMCP version installed:"
"$VENV/bin/pip" show fastmcp | grep Version
echo ""

# ── [5/8] Copy application files from staging area ────────────────────────────
echo "--- [5/8] Copying application files from $STAGING ---"
if [[ ! -d "$STAGING" ]]; then
    echo "ERROR: Staging directory $STAGING not found."
    echo "SCP the repo files to the server first:"
    echo "  scp -r server   user@YOUR_MCP_SERVER_IP:/tmp/mcp-demo-deploy/server"
    echo "  scp -r systemd  user@YOUR_MCP_SERVER_IP:/tmp/mcp-demo-deploy/systemd"
    exit 1
fi

cp "$STAGING/server/mcp_server.py"    "$DEMO_DIR/mcp_server.py"
cp "$STAGING/server/requirements.txt" "$DEMO_DIR/requirements.txt"
cp "$STAGING/server/setup_demo_db.py" "$DEMO_DIR/setup_demo_db.py"

echo "Files copied to $DEMO_DIR:"
ls -la "$DEMO_DIR"
echo ""

# ── [6/8] Create demo database ────────────────────────────────────────────────
echo "--- [6/8] Seeding demo database ---"
"$VENV/bin/python" "$DEMO_DIR/setup_demo_db.py"
echo ""

# ── [7/8] Install and start systemd service ───────────────────────────────────
echo "--- [7/8] Installing systemd service ---"
cp "$STAGING/systemd/mcp-demo.service" "$SERVICE_FILE"

# Fix ownership: server process needs read access to its own files
chown -R "$SERVICE_USER:$SERVICE_USER" "$DEMO_DIR"
# /pipeline is owned by root but readable by all — the service user can read it
chown root:root "$PIPELINE_DIR"
chmod 755 "$PIPELINE_DIR"

systemctl daemon-reload
systemctl enable mcp-demo
systemctl restart mcp-demo

echo ""

# ── [8/8] Verify ──────────────────────────────────────────────────────────────
echo "--- [8/8] Verifying service ---"
sleep 3  # give uvicorn a moment to bind

systemctl status mcp-demo --no-pager

echo ""
if ss -tlnp | grep -q 8008; then
    echo "OK: Port 8008 is LISTENING"
else
    echo "WARNING: Port 8008 is NOT listening — check: journalctl -u mcp-demo -n 50"
fi

echo ""
echo "Quick loopback test (tools/list):"
curl -s -X POST http://127.0.0.1:8008/mcp \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
    | python3 -m json.tool 2>/dev/null | grep '"name"' || echo "(no JSON response — check logs)"

echo ""
echo "================================================================"
echo "  Provisioning complete."
echo "  Next step: run test_baseline.sh to verify the server directly,"
echo "  then update your FortiWeb server pool to point to this host on port 8008."
echo "================================================================"
