#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REMOTE_HOST="${VPN233_REMOTE_HOST:-8.163.25.145}"
REMOTE_PORT="${VPN233_REMOTE_PORT:-22}"
REMOTE_USER="${VPN233_REMOTE_USER:-root}"
REMOTE_PASSWORD="${VPN233_REMOTE_PASSWORD:-}"
REMOTE_DIR="${VPN233_REMOTE_DIR:-/tmp/vpn233-provider-verify}"
VERIFY_PORT="${VPN233_REMOTE_VERIFY_PORT:-18888}"
VERIFY_TOKEN="${VPN233_REMOTE_VERIFY_TOKEN:-verify-token}"
VERIFY_TIMEOUT="${VPN233_REMOTE_VERIFY_TIMEOUT:-30}"
LOCAL_TMP_DIR="$(mktemp -d)"
ARCHIVE_LOCAL="${LOCAL_TMP_DIR}/vpn233-provider-workspace.tar.gz"
ARCHIVE_REMOTE="/tmp/vpn233-provider-workspace.tar.gz"
WORKER_LOCAL="${LOCAL_TMP_DIR}/verify-remote-worker.sh"

cleanup_local() {
  rm -rf "$LOCAL_TMP_DIR"
}
trap cleanup_local EXIT

SSH_OPTS=(
  "-o" "StrictHostKeyChecking=no"
  "-o" "UserKnownHostsFile=/dev/null"
  "-o" "BatchMode=yes"
  "-o" "ConnectTimeout=10"
  "-p" "$REMOTE_PORT"
)
SCP_OPTS=(
  "-P" "$REMOTE_PORT"
  "-o" "StrictHostKeyChecking=no"
  "-o" "UserKnownHostsFile=/dev/null"
  "-o" "BatchMode=yes"
  "-o" "ConnectTimeout=10"
)

ssh_exec() {
  if [[ -n "${REMOTE_PASSWORD}" ]] && command -v sshpass >/dev/null 2>&1; then
    sshpass -p "${REMOTE_PASSWORD}" ssh "${SSH_OPTS[@]}" "${REMOTE_USER}@${REMOTE_HOST}" "$@"
    return
  fi
  if [[ -n "${REMOTE_PASSWORD}" ]] && ! command -v sshpass >/dev/null 2>&1; then
    echo "[warn] 未检测到 sshpass，将尝试交互式 SSH 登录（建议改用 SSH key）" >&2
  fi
  ssh "${SSH_OPTS[@]}" "${REMOTE_USER}@${REMOTE_HOST}" "$@"
}

scp_put() {
  local src=$1
  local dst=$2
  if [[ -n "${REMOTE_PASSWORD}" ]] && command -v sshpass >/dev/null 2>&1; then
    sshpass -p "${REMOTE_PASSWORD}" scp "${SCP_OPTS[@]}" "${src}" "${REMOTE_USER}@${REMOTE_HOST}:${dst}"
    return
  fi
  scp "${SCP_OPTS[@]}" "${src}" "${REMOTE_USER}@${REMOTE_HOST}:${dst}"
}

check_prereqs() {
  for cmd in ssh scp curl tar go mktemp; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "[error] missing command: $cmd"; exit 1; }
  done
}

build_remote_payload() {
  cat > "$WORKER_LOCAL" <<'REMOTE_PAYLOAD_EOF'
#!/usr/bin/env bash
set -euo pipefail

REMOTE_DIR="${REMOTE_DIR:?}"
VERIFY_PORT="${VERIFY_PORT:?}"
VERIFY_TOKEN="${VERIFY_TOKEN:?}"
VERIFY_TIMEOUT="${VERIFY_TIMEOUT:?}"
SOURCE_ARCHIVE="${SOURCE_ARCHIVE:?}"

is_port_open() {
  local port="$1"
  (echo >/dev/tcp/127.0.0.1/"$port") >/dev/null 2>&1
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

FREE_PORT="$(pick_free_port "$VERIFY_PORT")"
if [[ -z "$FREE_PORT" ]]; then
  echo "[remote-verify] no free port around $VERIFY_PORT"
  exit 1
fi
VERIFY_PORT="$FREE_PORT"

CFG_FILE="$REMOTE_DIR/server.yaml"
LOG_FILE="$REMOTE_DIR/server.log"

case "$REMOTE_DIR" in
  /tmp/*|/var/tmp/*) ;;
  *)
    echo "[remote-verify] REMOTE_DIR must stay under /tmp or /var/tmp, got: $REMOTE_DIR"
    exit 1
    ;;
esac

rm -rf "$REMOTE_DIR"
mkdir -p "$REMOTE_DIR"
tar -xzf "$SOURCE_ARCHIVE" -C "$REMOTE_DIR"

cat >"$CFG_FILE" <<YAML
listen_addr: "127.0.0.1"
listen_port: ${VERIFY_PORT}
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
subscribe_verify_token: "${VERIFY_TOKEN}"
proxysss:
  enabled: true
  admin_url: "http://127.0.0.1:7777"
  bearer_token: "proxysss-remote-test-token"
  provider_subdomain: "panel"
  upstream: "http://127.0.0.1:${VERIFY_PORT}"
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

function cleanup() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -f "$SOURCE_ARCHIVE"
}
trap cleanup EXIT

cd "$REMOTE_DIR"
export VPN233_CONFIG_PATH="$CFG_FILE"

go test ./...

go run . >"$LOG_FILE" 2>&1 &
SERVER_PID=$!

BASE_URL="http://127.0.0.1:${VERIFY_PORT}"
for i in $(seq 1 "${VERIFY_TIMEOUT}"); do
  if curl -fs "${BASE_URL}/api/v1/health" >/dev/null; then
    break
  fi
  sleep 1
done

if ! curl -fs "${BASE_URL}/api/v1/health" >/dev/null; then
  echo "[remote-verify] health check failed"
  cat "$LOG_FILE"
  exit 1
fi

LOGIN=$(curl -fs -X POST "${BASE_URL}/api/v1/login" -H 'Content-Type: application/json' --data '{"username":"root","password":"root"}')
TOKEN=$(printf '%s' "$LOGIN" | sed -n 's/.*"token":[[:space:]]*"\([^"]*\)".*/\1/p')
if [[ -z "$TOKEN" ]]; then
  echo "[remote-verify] login failed"
  cat "$LOG_FILE"
  exit 1
fi

PROTOCOLS=$(curl -fs "${BASE_URL}/api/v1/protocols?node_ip=edge.example.com")
echo "$PROTOCOLS" | head -n 1
curl -fs "${BASE_URL}/api/v1/repo/status" -H "Authorization: Bearer $TOKEN" | head -n 1
curl -fs "${BASE_URL}/api/v1/subscribe/verify?token=${VERIFY_TOKEN}" | head -n 1
curl -fs "${BASE_URL}/api/v1/subscribe/convert?token=${VERIFY_TOKEN}&target=clash-meta-nekotls&node_ip=203.0.113.10&use_mihomo=true" | grep -q "type:[[:space:]]*nekotls"

GEN=$(curl -fs "${BASE_URL}/api/v1/local/generate.sh?node_name=remote-verify&node_ip=edge.example.com&use_singbox=true&selected_protocols=singbox-nekotls")
for kw in tune_performance apply_security_hardening install_watchdog issue_acme_cert; do
  echo "$GEN" | grep -q "$kw" || { echo "[remote-verify] missing $kw"; exit 1; }
done

GATEWAY=$(curl -fs "${BASE_URL}/api/v1/local/gateway/proxysss.yaml")
echo "$GATEWAY" | grep -q "challenge: dns01"
echo "$GATEWAY" | grep -q "provider: cloudflare"
echo "$GATEWAY" | grep -q "name: vpn233-provider-panel"

PROTO_IDS=( $(echo "$PROTOCOLS" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | tr '\n' ' ') )
if (( ${#PROTO_IDS[@]} == 0 )); then
  echo "[remote-verify] protocol catalog extraction failed"
  exit 1
fi

for pid in "${PROTO_IDS[@]}"; do
  SAMPLE=$(curl -fs "${BASE_URL}/api/v1/local/generate.sh?node_name=proto-${pid}&node_ip=203.0.113.10&use_singbox=true&use_mihomo=true&selected_protocols=${pid}")
  echo "$SAMPLE" | head -n 1 | grep -q "#!/usr/bin/env bash" || { echo "[remote-verify] generate failed: $pid"; exit 1; }
  echo "$SAMPLE" | grep -q "vpn233-node" || { echo "[remote-verify] helper marker missing: $pid"; exit 1; }
done

echo "[remote-verify] protocol matrix ok"

echo "[remote-verify] ok"
echo "[remote-verify] logs:"
cat "$LOG_FILE"
REMOTE_PAYLOAD_EOF
}

check_prereqs
tar --exclude='.git' --exclude='.git\\*' -czf "$ARCHIVE_LOCAL" -C "$ROOT_DIR" .
build_remote_payload

echo "[remote-verify] upload verify worker"
scp_put "$ARCHIVE_LOCAL" "$ARCHIVE_REMOTE"
scp_put "$WORKER_LOCAL" "/tmp/verify-remote-worker.sh"

ssh_exec "chmod +x /tmp/verify-remote-worker.sh && REMOTE_DIR='${REMOTE_DIR}' VERIFY_PORT='${VERIFY_PORT}' VERIFY_TOKEN='${VERIFY_TOKEN}' VERIFY_TIMEOUT='${VERIFY_TIMEOUT}' SOURCE_ARCHIVE='${ARCHIVE_REMOTE}' /tmp/verify-remote-worker.sh"
ssh_exec "rm -f /tmp/verify-remote-worker.sh"

echo "[remote-verify] done"
