param(
    [string]$RemoteHost = $(if ($env:VPN233_REMOTE_HOST) { $env:VPN233_REMOTE_HOST } else { "8.163.25.145" }),
    [int]$RemotePort = $(if ($env:VPN233_REMOTE_PORT) { [int]$env:VPN233_REMOTE_PORT } else { 22 }),
    [string]$RemoteUser = $(if ($env:VPN233_REMOTE_USER) { $env:VPN233_REMOTE_USER } else { "root" }),
    [string]$RemotePassword = $(if ($env:VPN233_REMOTE_PASSWORD) { $env:VPN233_REMOTE_PASSWORD } else { "" }),
    [string]$RemoteDir = $(if ($env:VPN233_REMOTE_DIR) { $env:VPN233_REMOTE_DIR } else { "/tmp/vpn233-provider-verify" }),
    [int]$VerifyPort = $(if ($env:VPN233_REMOTE_VERIFY_PORT) { [int]$env:VPN233_REMOTE_VERIFY_PORT } else { 18888 }),
    [string]$VerifyToken = $(if ($env:VPN233_REMOTE_VERIFY_TOKEN) { $env:VPN233_REMOTE_VERIFY_TOKEN } else { "verify-token" }),
    [int]$VerifyTimeout = $(if ($env:VPN233_REMOTE_VERIFY_TIMEOUT) { [int]$env:VPN233_REMOTE_VERIFY_TIMEOUT } else { 30 })
)

$ErrorActionPreference = "Stop"
$workspaceRoot = Split-Path -Parent $PSScriptRoot

$script:RemoteHost = $RemoteHost
$script:RemotePort = $RemotePort
$script:RemoteUser = $RemoteUser
$script:RemotePassword = if ($PSBoundParameters.ContainsKey("RemotePassword")) { $PSBoundParameters["RemotePassword"] } else { $RemotePassword }
$script:SshSession = $null
$script:UsePoshSsh = $false

function Test-Prereqs {
    param([string[]]$Commands)
    foreach ($cmd in $Commands) {
        if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
            throw "[error] missing command: $cmd"
        }
    }
}

function Invoke-RemoteShell {
    param([string]$Command, [bool]$NeedSudo = $false)
    if ($script:UsePoshSsh -and $script:SshSession) {
        $finalCommand = if ($NeedSudo) { "sudo bash -lc {0}" -f $Command } else { $Command }
        $result = Invoke-SSHCommand -SessionId $script:SshSession.SessionId -Command $finalCommand -ErrorAction Stop
        if ($result.ExitStatus -ne 0) {
            throw "[error] remote command failed: $Command"
        }
        $result.Output | ForEach-Object { Write-Output $_ }
        return
    }

    $quoteCommand = [string]::Format("`"{0}`"", $Command)
    if ($script:RemotePassword) {
        if (Get-Command sshpass -ErrorAction SilentlyContinue) {
            if ($NeedSudo) {
                $cmd = @("sshpass", "-p", $script:RemotePassword, "ssh", "-p", $script:RemotePort, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=no", "-o", "ConnectTimeout=10", "$script:RemoteUser@$script:RemoteHost", "sudo", "bash", "-lc", $quoteCommand)
                & $cmd[0] $cmd[1..($cmd.Length-1)]
                if ($LASTEXITCODE -ne 0) {
                    throw "[error] sshpass command failed: $($cmd -join ' ')"
                }
            } else {
                $cmd = @("sshpass", "-p", $script:RemotePassword, "ssh", "-p", $script:RemotePort, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=no", "-o", "ConnectTimeout=10", "$script:RemoteUser@$script:RemoteHost", $quoteCommand)
                & $cmd[0] $cmd[1..($cmd.Length-1)]
                if ($LASTEXITCODE -ne 0) {
                    throw "[error] sshpass command failed: $($cmd -join ' ')"
                }
            }
            return
        }
        Write-Host "[warn] 未检测到 sshpass；若未建立 Posh-SSH 会话，请确认是否已配置 SSH key 或已设置 VPN233_REMOTE_PASSWORD 可自动登录" -ForegroundColor Yellow
        throw "[error] 当前环境未检测到 sshpass，无法进行密码登录"
    }
    if ($NeedSudo) {
        ssh -p $script:RemotePort -o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null" -o "BatchMode=yes" -o "ConnectTimeout=10" "$script:RemoteUser@$script:RemoteHost" "sudo bash -lc $quoteCommand"
        if ($LASTEXITCODE -ne 0) {
            throw "[error] ssh command failed: ssh $script:RemoteUser@$script:RemoteHost"
        }
    } else {
        ssh -p $script:RemotePort -o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null" -o "BatchMode=yes" -o "ConnectTimeout=10" "$script:RemoteUser@$script:RemoteHost" $quoteCommand
        if ($LASTEXITCODE -ne 0) {
            throw "[error] ssh command failed: ssh $script:RemoteUser@$script:RemoteHost"
        }
    }
}

function Copy-RemoteFile {
    param([string]$LocalPath, [string]$RemotePath)
    if ($script:UsePoshSsh -and $script:SshSession) {
        Set-SCPFile -SessionId $script:SshSession.SessionId -LocalFile $LocalPath -RemotePath $RemotePath | Out-Null
        return
    }
    if ($script:RemotePassword -and (Get-Command sshpass -ErrorAction SilentlyContinue)) {
        sshpass -p $script:RemotePassword scp -P $script:RemotePort -o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null" -o "BatchMode=no" -o "ConnectTimeout=10" $LocalPath "$script:RemoteUser@$script:RemoteHost`:$RemotePath"
        if ($LASTEXITCODE -ne 0) {
            throw "[error] scp failed: $($LocalPath) -> $script:RemoteUser@$script:RemoteHost`:$RemotePath"
        }
    } elseif ($script:RemotePassword) {
        throw "[error] 当前环境未检测到 sshpass 且未建立 Posh-SSH 会话，无法进行密码文件拷贝"
    } else {
        scp -P $script:RemotePort -o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null" -o "BatchMode=yes" -o "ConnectTimeout=10" $LocalPath "$script:RemoteUser@$script:RemoteHost`:$RemotePath"
        if ($LASTEXITCODE -ne 0) {
            throw "[error] scp failed: $($LocalPath) -> $script:RemoteUser@$script:RemoteHost`:$RemotePath"
        }
    }
}

function Ensure-RemoteSession {
    if ($script:RemotePassword -and -not (Get-Command sshpass -ErrorAction SilentlyContinue)) {
        try {
            if (-not (Get-Module -ListAvailable -Name Posh-SSH)) {
                if (-not $script:RemotePassword) { return }
                throw "[error] 需要密码登录时未检测到 sshpass 或 Posh-SSH"
            }
            if (-not (Get-Module -Name Posh-SSH)) {
                Import-Module Posh-SSH -ErrorAction Stop | Out-Null
            }
            $securePass = ConvertTo-SecureString $script:RemotePassword -AsPlainText -Force
            $cred = New-Object System.Management.Automation.PSCredential ($script:RemoteUser, $securePass)
            $script:SshSession = New-SSHSession -ComputerName $script:RemoteHost -Port $script:RemotePort -Credential $cred -AcceptKey -ConnectionTimeout 5 -WarningAction SilentlyContinue -ErrorAction Stop
            $script:UsePoshSsh = $true
            Write-Host "[info] 使用 Posh-SSH 建立密码会话成功" -ForegroundColor Green
            return
        }
        catch {
            if ($script:RemotePassword) {
                throw "[error] Posh-SSH 会话建立失败：$($_.Exception.Message)。请确认密码与账号，或使用 SSH key"
            }
            $script:UsePoshSsh = $false
        }
    }
}

Write-Host "[step] loading local prerequisites"
Test-Prereqs @("ssh", "scp", "go")

Write-Host "[step] establishing remote session"
Ensure-RemoteSession

$tmpRoot = Join-Path $env:TEMP ("vpn233-verify-remote-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmpRoot -Force | Out-Null
Write-Host "[step] working directory: $tmpRoot"

$archivePath = Join-Path $tmpRoot "vpn233-provider-workspace.tar.gz"
$remoteArchivePath = "/tmp/vpn233-provider-workspace.tar.gz"
$tarExe = (Get-Command tar -ErrorAction Stop).Source
& $tarExe "-czf" $archivePath "--exclude=.git" "-C" $workspaceRoot "."
if ($LASTEXITCODE -ne 0) {
    throw "[error] failed to build workspace archive"
}

$localWorker = Join-Path $tmpRoot "verify-remote-worker.sh"
$payload = @'
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

echo "[remote-verify] ok"
echo "[remote-verify] logs:"
cat "$LOG_FILE"
'@
Set-Content -Path $localWorker -Encoding UTF8 -Value $payload

$remoteWorkerPath = "/tmp/verify-remote-worker.sh"
Write-Host "[step] upload remote worker"
Copy-RemoteFile -LocalPath $archivePath -RemotePath $remoteArchivePath
Copy-RemoteFile -LocalPath $localWorker -RemotePath $remoteWorkerPath

try {
    Write-Host "[step] run remote verification worker"
    $cmd = "chmod +x $remoteWorkerPath && REMOTE_DIR='$RemoteDir' VERIFY_PORT='$VerifyPort' VERIFY_TOKEN='$VerifyToken' VERIFY_TIMEOUT='$VerifyTimeout' SOURCE_ARCHIVE='$remoteArchivePath' $remoteWorkerPath"
    Invoke-RemoteShell -Command $cmd
    Write-Host "[remote-verify] done" -ForegroundColor Green
} finally {
    Invoke-RemoteShell -Command "rm -f $remoteWorkerPath"
    Remove-Item -Path $tmpRoot -Recurse -Force
    if ($script:SshSession) {
        Remove-SSHSession -SessionId $script:SshSession.SessionId | Out-Null
    }
}
