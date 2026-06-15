#!/usr/bin/env bash
set -euo pipefail

PORT="${VPN233_VERIFY_PORT:-18888}"
VERIFY_TOKEN="${VPN233_VERIFY_TOKEN:-verify-token}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
CFG_FILE="$TMP_DIR/agent-config.json"
LOG_FILE="$TMP_DIR/server.log"
ORIG_CFG="$ROOT_DIR/agent-config.json"
BACKUP_CFG=""

cat >"$CFG_FILE" <<JSON
{
  "listen_addr": "127.0.0.1",
  "listen_port": $PORT,
  "admin_user": "root",
  "admin_password": "root",
  "default_data_dir": "/tmp/vpn233",
  "default_node_ip": "",
  "default_port_base": 10000,
  "default_enable_bbr": true,
  "default_use_mihomo": false,
  "default_use_singbox": true,
  "subscribe_repo_url": "https://github.com/neko233-com/vpn233-subscribe-server.git",
  "subscribe_repo_path": "vpn233-subscribe-server",
  "subscribe_repo_branch": "main",
  "subscribe_verify_token": "$VERIFY_TOKEN"
}
JSON

cleanup() {
  if [[ -n "$BACKUP_CFG" ]] && [[ -f "$BACKUP_CFG" ]]; then
    mv -f "$BACKUP_CFG" "$ORIG_CFG"
  elif [[ -f "$ORIG_CFG" ]] && [[ ! -f "$TMP_DIR/agent-config.json.orig" ]]; then
    rm -f "$ORIG_CFG"
  fi
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "[verify] run tests"
go test ./...

if [[ -f "$ORIG_CFG" ]]; then
  cp "$ORIG_CFG" "$TMP_DIR/agent-config.json.orig"
  BACKUP_CFG="$TMP_DIR/agent-config.json.orig"
fi
cp "$CFG_FILE" "$ORIG_CFG"

echo "[verify] start provider server"
(
  cd "$ROOT_DIR"
  go run . >"$LOG_FILE" 2>&1
) &
SERVER_PID=$!

for i in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:$PORT/api/v1/health" >/dev/null; then
    break
  fi
  sleep 1
done

echo "[verify] health"
curl -sf "http://127.0.0.1:$PORT/api/v1/health" | head -n 1

LOGIN=$(curl -sf -X POST "http://127.0.0.1:$PORT/api/v1/login" \
  -H 'Content-Type: application/json' \
  --data '{"username":"root","password":"root"}')
TOKEN=$(echo "$LOGIN" | sed -n 's/.*"token":[[:space:]]*"\([^"]*\)".*/\1/p')

if [[ -z "$TOKEN" ]]; then
  echo "[verify] login failed"
  echo "$LOGIN"
  exit 1
fi

echo "[verify] repo status"
curl -sf -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/api/v1/repo/status" | head -n 1

echo "[verify] protocols"
curl -sf "http://127.0.0.1:$PORT/api/v1/protocols" | head -n 1

echo "[verify] subscribe verify"
curl -sf "http://127.0.0.1:$PORT/api/v1/subscribe/verify?token=$VERIFY_TOKEN" | head -n 1

echo "[verify] protocols include nekotls"
curl -sf "http://127.0.0.1:$PORT/api/v1/protocols" | grep -q "nekotls" || { echo "[verify] nekotls missing from catalog"; exit 1; }

echo "[verify] subscribe convert clash-meta-nekotls"
CONVERT=$(curl -sf "http://127.0.0.1:$PORT/api/v1/subscribe/convert?target=clash-meta-nekotls&node_ip=203.0.113.10&use_mihomo=true&token=$VERIFY_TOKEN")
if ! echo "$CONVERT" | grep -q "type: nekotls"; then
  echo "[verify] nekotls subscribe conversion missing type: nekotls"
  exit 1
fi
echo "[verify] nekotls subscribe conversion ok"

echo "[verify] node generation features"
GEN=$(curl -sf "http://127.0.0.1:$PORT/api/v1/local/generate.sh?node_name=v&node_ip=edge.example.com&enable_acme=true&acme_domain=edge.example.com&selected_protocols=singbox-nekotls")
for kw in tune_performance apply_security_hardening install_watchdog issue_acme_cert; do
  echo "$GEN" | grep -q "$kw" || { echo "[verify] generated node script missing $kw"; exit 1; }
done
echo "[verify] node generation features ok"

echo "[verify] done"
