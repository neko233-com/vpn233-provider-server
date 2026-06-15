#!/usr/bin/env bash
# Generate a maximal install script and bash -n syntax-check both the outer
# installer and the embedded vpn233-node management CLI.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

cd "$ROOT_DIR"
PROTOCOLS="singbox-nekotls,mihomo-nekotls,singbox-vless-reality-grpc,singbox-wireguard,singbox-hysteria2,singbox-tuic,singbox-trojan,singbox-shadowsocks,mihomo-vless-reality-grpc"

go run . generate --format sh --node-name syntax-node --node-ip 203.0.113.10 \
  --use-singbox=true --use-mihomo=true --enable-acme=true --acme-domain edge.example.com \
  --enable-fail2ban=true --enable-watchdog=true --enable-hardening=true \
  --protocols "$PROTOCOLS" >"$TMP_DIR/install.sh" 2>/dev/null

echo "[syntax] outer installer"
bash -n "$TMP_DIR/install.sh"

echo "[syntax] inner vpn233-node CLI"
awk '/cat >\/usr\/local\/bin\/vpn233-node <<EOF/{f=1;next} f&&/^EOF$/{f=0} f' \
  "$TMP_DIR/install.sh" | sed -E 's/\\([$`\\])/\1/g' >"$TMP_DIR/vpn233-node.sh"
bash -n "$TMP_DIR/vpn233-node.sh"

echo "[syntax] OK"
