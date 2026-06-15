#!/usr/bin/env bash
set -euo pipefail

PORT="${VPN233_VERIFY_PORT:-18888}"
VERIFY_TOKEN="${VPN233_VERIFY_TOKEN:-verify-token}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
LOG_FILE="$TMP_DIR/server.log"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

is_port_open() {
  local port="$1"
  (echo > /dev/tcp/127.0.0.1/"$port") >/dev/null 2>&1
}

pick_free_port() {
  local p="$1"
  local limit=$((p + 60))
  while (( p <= limit )); do
    if ! is_port_open "$p"; then
      echo "$p"
      return 0
    fi
    p=$((p + 1))
  done
  return 1
}

FREE_PORT="$(pick_free_port "$PORT")"
if [[ -z "$FREE_PORT" ]]; then
  echo "[verify] no free port around $PORT"
  exit 1
fi
PORT="$FREE_PORT"
CFG_FILE="$(mktemp "${TMP_DIR}/server-XXXXXX.yaml")"

cat >"$CFG_FILE" <<YAML
listen_addr: "127.0.0.1"
listen_port: $PORT
admin_user: "root"
admin_password: "root"
default_data_dir: "/tmp/vpn233"
default_node_ip: ""
default_port_base: 10000
default_enable_bbr: true
default_use_mihomo: false
default_use_singbox: true
subscribe_repo_url: "https://github.com/neko233-com/vpn233-subscribe-server.git"
subscribe_repo_path: "vpn233-subscribe-server"
subscribe_repo_branch: "main"
subscribe_verify_token: "$VERIFY_TOKEN"
proxysss:
  enabled: true
  admin_url: "http://127.0.0.1:7777"
  bearer_token: "proxysss-test-token"
  provider_subdomain: "panel"
  upstream: "http://127.0.0.1:$PORT"
dns_automation:
  enabled: true
  provider: "cloudflare"
  api_token: "cf-test-token"
  email: "ops@example.com"
  base_domain: "example.com"
  production: true
  challenge: "dns01"
  create_wildcard: true
YAML

echo "[verify] run tests"
go test ./...

echo "[verify] start provider server"
(
  cd "$ROOT_DIR"
  VPN233_CONFIG_PATH="$CFG_FILE" go run . >"$LOG_FILE" 2>&1
) &
SERVER_PID=$!
sleep 0.3
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "[verify] server process exited unexpectedly"
  cat "$LOG_FILE"
  exit 1
fi

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
PROTO_JSON=$(curl -sf "http://127.0.0.1:$PORT/api/v1/protocols?node_ip=edge.example.com")
echo "$PROTO_JSON" | head -n 1
if ! echo "$PROTO_JSON" | grep -q '"id":"singbox-nekotls"' || ! echo "$PROTO_JSON" | grep -q '"id":"mihomo-nekotls"'; then
  echo "[verify] protocol catalog from API does not include NekoTLS templates"
  exit 1
fi
PROTO_IDS=($(echo "$PROTO_JSON" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p'))
if (( ${#PROTO_IDS[@]} == 0 )); then
  echo "[verify] protocol catalog extraction failed"
  exit 1
fi
echo "[verify] protocol matrix generation"
for pid in "${PROTO_IDS[@]}"; do
  SAMPLE=$(curl -fs "http://127.0.0.1:$PORT/api/v1/local/generate.sh?node_name=proto-${pid}&node_ip=203.0.113.10&use_singbox=true&use_mihomo=true&selected_protocols=${pid}")
  echo "$SAMPLE" | head -n 1 | grep -q "#!/usr/bin/env bash" || { echo "[verify] protocol generate failed: $pid"; exit 1; }
  echo "$SAMPLE" | grep -q "vpn233-node" || { echo "[verify] protocol script missing helper marker: $pid"; exit 1; }
done

echo "[verify] subscribe verify"
curl -sf "http://127.0.0.1:$PORT/api/v1/subscribe/verify?token=$VERIFY_TOKEN" | head -n 1

echo "[verify] protocols include nekotls"
PROTO_CLI=$(go run . protocols)
echo "$PROTO_CLI" | grep -Eq '"id"[[:space:]]*:[[:space:]]*"singbox-nekotls"' || { echo "[verify] singbox nekotls missing from catalog"; exit 1; }
echo "$PROTO_CLI" | grep -Eq '"id"[[:space:]]*:[[:space:]]*"mihomo-nekotls"' || { echo "[verify] mihomo nekotls missing from catalog"; exit 1; }

echo "[verify] subscribe convert clash-meta-nekotls"
CONVERT=$(curl -sf "http://127.0.0.1:$PORT/api/v1/subscribe/convert?target=clash-meta-nekotls&node_ip=203.0.113.10&use_mihomo=true&token=$VERIFY_TOKEN")
if ! echo "$CONVERT" | grep -Eq "type:[[:space:]]*nekotls"; then
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

echo "[verify] proxysss gateway yaml"
GATEWAY=$(curl -sf "http://127.0.0.1:$PORT/api/v1/local/gateway/proxysss.yaml")
for kw in "challenge: dns01" "provider: cloudflare" "name: vpn233-provider-panel"; do
  echo "$GATEWAY" | grep -q "$kw" || { echo "[verify] proxysss gateway plan missing $kw"; exit 1; }
done
echo "[verify] proxysss gateway yaml ok"

echo "[verify] done"
