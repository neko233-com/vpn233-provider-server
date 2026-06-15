#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

INSTALL_DIR="${VPN233_INSTALL_DIR:-/opt/vpn233-provider-server}"
REPO_URL="${VPN233_PROVIDER_REPO_URL:-https://github.com/neko233-com/vpn233-provider-server.git}"
REPO_BRANCH="${VPN233_PROVIDER_BRANCH:-main}"
LISTEN_ADDR="${VPN233_LISTEN_ADDR:-0.0.0.0}"
LISTEN_PORT="${VPN233_LISTEN_PORT:-8080}"
ADMIN_USER="${VPN233_ADMIN_USER:-root}"
ADMIN_PASSWORD="${VPN233_ADMIN_PASSWORD:-root}"
SUB_REPO_URL="${VPN233_SUB_REPO_URL:-https://github.com/neko233-com/vpn233-subscribe-server.git}"
SUB_REPO_PATH="${VPN233_SUB_REPO_PATH:-vpn233-subscribe-server}"
SUB_REPO_BRANCH="${VPN233_SUB_REPO_BRANCH:-main}"
VERIFY_TOKEN="${VPN233_VERIFY_TOKEN:-}"
GO_VERSION="${VPN233_GO_VERSION:-1.26.0}"
PROXYSSS_ENABLED="${VPN233_PROXYSSS_ENABLED:-false}"
PROXYSSS_ADMIN_URL="${VPN233_PROXYSSS_ADMIN_URL:-http://127.0.0.1:7777}"
PROXYSSS_BEARER_TOKEN="${VPN233_PROXYSSS_BEARER_TOKEN:-}"
PROXYSSS_PROVIDER_DOMAIN="${VPN233_PROXYSSS_PROVIDER_DOMAIN:-}"
PROXYSSS_PROVIDER_SUBDOMAIN="${VPN233_PROXYSSS_PROVIDER_SUBDOMAIN:-panel}"
PROXYSSS_UPSTREAM="${VPN233_PROXYSSS_UPSTREAM:-http://127.0.0.1:8080}"
DNS_AUTOMATION_ENABLED="${VPN233_DNS_AUTOMATION_ENABLED:-false}"
DNS_PROVIDER="${VPN233_DNS_PROVIDER:-}"
DNS_API_TOKEN="${VPN233_DNS_API_TOKEN:-}"
DNS_EMAIL="${VPN233_DNS_EMAIL:-}"
DNS_BASE_DOMAIN="${VPN233_DNS_BASE_DOMAIN:-}"
DNS_CHALLENGE="${VPN233_DNS_CHALLENGE:-dns01}"

if [[ "$EUID" -ne 0 ]]; then
  echo "请使用 root 身份执行"
  exit 1
fi

detect_pkg_mgr() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt-get"
    return
  fi
  if command -v dnf >/dev/null 2>&1; then
    echo "dnf"
    return
  fi
  if command -v yum >/dev/null 2>&1; then
    echo "yum"
    return
  fi
  echo ""
}

install_packages() {
  local mgr
  mgr="$(detect_pkg_mgr)"
  case "$mgr" in
    apt-get)
      apt-get update -y
      apt-get install -y curl git tar gzip ca-certificates jq
      ;;
    dnf)
      dnf -y install curl git tar gzip ca-certificates jq
      ;;
    yum)
      yum -y install curl git tar gzip ca-certificates jq
      ;;
    *)
      echo "未识别的包管理器，请手动安装 curl/git/tar/gzip"
      ;;
  esac
}

install_go() {
  local arch target version
  version="$(go version 2>/dev/null || true)"
  if [[ "$version" == *"go${GO_VERSION%.*}"* ]]; then
    return
  fi
  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)
      echo "不支持的架构: $(uname -m)"
      exit 1
      ;;
  esac
  target="go${GO_VERSION}.linux-${arch}.tar.gz"
  curl -fsSL "https://go.dev/dl/${target}" -o "/tmp/${target}"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "/tmp/${target}"
  ln -sf /usr/local/go/bin/go /usr/local/bin/go
}

sync_repo() {
  if [[ -d "$INSTALL_DIR/.git" ]]; then
    git -C "$INSTALL_DIR" fetch origin "$REPO_BRANCH"
    git -C "$INSTALL_DIR" checkout -q "$REPO_BRANCH"
    git -C "$INSTALL_DIR" reset --hard "origin/$REPO_BRANCH"
    return
  fi
  rm -rf "$INSTALL_DIR"
  git clone --depth 1 -b "$REPO_BRANCH" "$REPO_URL" "$INSTALL_DIR"
}

write_config() {
  cat >"$INSTALL_DIR/server.yaml" <<EOF
listen_addr: "${LISTEN_ADDR}"
listen_port: ${LISTEN_PORT}
admin_user: "${ADMIN_USER}"
admin_password: "${ADMIN_PASSWORD}"
default_data_dir: "/etc/vpn233"
default_node_ip: ""
default_port_base: 10000
default_enable_bbr: true
default_use_mihomo: true
default_use_singbox: true
subscribe_repo_url: "${SUB_REPO_URL}"
subscribe_repo_path: "${SUB_REPO_PATH}"
subscribe_repo_branch: "${SUB_REPO_BRANCH}"
subscribe_verify_token: "${VERIFY_TOKEN}"
proxysss:
  enabled: ${PROXYSSS_ENABLED}
  admin_url: "${PROXYSSS_ADMIN_URL}"
  bearer_token: "${PROXYSSS_BEARER_TOKEN}"
  provider_domain: "${PROXYSSS_PROVIDER_DOMAIN}"
  provider_subdomain: "${PROXYSSS_PROVIDER_SUBDOMAIN}"
  upstream: "${PROXYSSS_UPSTREAM}"
dns_automation:
  enabled: ${DNS_AUTOMATION_ENABLED}
  provider: "${DNS_PROVIDER}"
  api_token: "${DNS_API_TOKEN}"
  email: "${DNS_EMAIL}"
  base_domain: "${DNS_BASE_DOMAIN}"
  production: true
  challenge: "${DNS_CHALLENGE}"
  create_wildcard: true
EOF
}

build_binary() {
  export PATH="/usr/local/go/bin:${PATH}"
  (cd "$INSTALL_DIR" && go build -o "$INSTALL_DIR/vpn233-provider-server" .)
}

install_service() {
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "系统没有 systemd，改为后台启动"
    pkill -f "$INSTALL_DIR/vpn233-provider-server" 2>/dev/null || true
    nohup "$INSTALL_DIR/vpn233-provider-server" > /var/log/vpn233-provider-server.log 2>&1 &
    return
  fi
  cat >/etc/systemd/system/vpn233-provider-server.service <<EOF
[Unit]
Description=vpn233-provider-server
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
Environment=VPN233_CONFIG_PATH=$INSTALL_DIR/server.yaml
ExecStart=$INSTALL_DIR/vpn233-provider-server
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now vpn233-provider-server
}

open_panel_port() {
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "$LISTEN_PORT"/tcp >/dev/null 2>&1 || true
    return
  fi
  if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --zone=public --add-port="$LISTEN_PORT/tcp" --permanent >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    return
  fi
  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p tcp --dport "$LISTEN_PORT" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$LISTEN_PORT" -j ACCEPT
  fi
}

install_helper_command() {
  cat >/usr/local/bin/vpn233-provider <<EOF
#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="$INSTALL_DIR"
BASE_URL="http://127.0.0.1:$LISTEN_PORT"
case "\${1:-help}" in
  status)
    command -v systemctl >/dev/null 2>&1 && systemctl status vpn233-provider-server --no-pager || true
    ;;
  restart)
    command -v systemctl >/dev/null 2>&1 && systemctl restart vpn233-provider-server || {
      pkill -f "\$INSTALL_DIR/vpn233-provider-server" 2>/dev/null || true
      nohup "\$INSTALL_DIR/vpn233-provider-server" >/var/log/vpn233-provider-server.log 2>&1 &
    }
    ;;
  logs)
    command -v journalctl >/dev/null 2>&1 && journalctl -u vpn233-provider-server -n 100 --no-pager || tail -n 100 /var/log/vpn233-provider-server.log
    ;;
  config)
    cat "\$INSTALL_DIR/server.yaml"
    ;;
  health)
    curl -fsSL "\$BASE_URL/api/v1/health"
    ;;
  gateway-plan)
    curl -fsSL "\$BASE_URL/api/v1/local/gateway/proxysss.yaml"
    ;;
  gateway-register)
    curl -fsSL -X POST "\$BASE_URL/api/v1/local/gateway/register"
    ;;
  repo-status)
    TOKEN="\${2:-}"
    test -n "\$TOKEN" || { echo "usage: vpn233-provider repo-status <token>"; exit 1; }
    curl -fsSL -H "Authorization: Bearer \$TOKEN" "\$BASE_URL/api/v1/repo/status"
    ;;
  *)
    cat <<USAGE
vpn233-provider status
vpn233-provider restart
vpn233-provider logs
vpn233-provider config
vpn233-provider health
vpn233-provider gateway-plan
vpn233-provider gateway-register
vpn233-provider repo-status <token>
USAGE
    ;;
esac
EOF
  chmod 755 /usr/local/bin/vpn233-provider
}

verify_service_health() {
  local url="http://127.0.0.1:$LISTEN_PORT/api/v1/health"
  for _ in $(seq 1 30); do
    if curl -fsSL --max-time 3 "$url" >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  echo "vpn233-provider-server 启动后未通过健康检查"
  command -v journalctl >/dev/null 2>&1 && journalctl -u vpn233-provider-server -n 100 --no-pager || true
  exit 1
}

install_packages
install_go
sync_repo
write_config
build_binary
install_service
open_panel_port
install_helper_command
verify_service_health

cat <<EOF
========================================
vpn233-provider-server 已安装
目录: $INSTALL_DIR
地址: http://$LISTEN_ADDR:$LISTEN_PORT/
账号: $ADMIN_USER
密码: $ADMIN_PASSWORD
订阅仓库: $SUB_REPO_URL
订阅分支: $SUB_REPO_BRANCH
管理命令: vpn233-provider
========================================
EOF
