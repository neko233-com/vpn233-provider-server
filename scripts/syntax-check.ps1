#requires -version 5.1
# Generate a maximal install script and bash -n syntax-check both the outer
# installer and the embedded vpn233-node management CLI. Requires Git Bash.
param(
    [string]$BashExe = ""
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

if (-not $BashExe) {
    $candidates = @(
        "C:\Program Files\Git\bin\bash.exe",
        "C:\Program Files\Git\usr\bin\bash.exe",
        "$env:LOCALAPPDATA\Programs\Git\bin\bash.exe"
    )
    $BashExe = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $BashExe) { throw "bash not found; install Git for Windows or pass -BashExe" }

$tmp = Join-Path $env:TEMP ("vpn233-syntax-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding($false)
try {
    Push-Location $root
    $protocols = "singbox-nekotls,mihomo-nekotls,singbox-vless-reality-grpc,singbox-wireguard,singbox-hysteria2,singbox-tuic,singbox-trojan,singbox-shadowsocks,mihomo-vless-reality-grpc"
    $sh = & go run . generate --format sh --node-name syntax-node --node-ip 203.0.113.10 `
        --use-singbox=true --use-mihomo=true --enable-acme=true --acme-domain edge.example.com `
        --enable-fail2ban=true --enable-watchdog=true --enable-hardening=true `
        --protocols $protocols 2>$null | Out-String
    $installPath = Join-Path $tmp "install.sh"
    [System.IO.File]::WriteAllText($installPath, $sh, $utf8)

    Write-Host "[syntax] outer installer"
    & $BashExe -n $installPath
    if ($LASTEXITCODE -ne 0) { throw "outer installer syntax error" }

    Write-Host "[syntax] inner vpn233-node CLI"
    $lines = Get-Content $installPath
    $start = ($lines | Select-String -SimpleMatch 'cat >/usr/local/bin/vpn233-node <<EOF').LineNumber
    $rest = $lines[$start..($lines.Count - 1)]
    $end = ($rest | Select-String -Pattern '^EOF$').LineNumber[0]
    $body = $rest[0..($end - 2)] | ForEach-Object { $_ -replace '\\([$`\\])', '$1' }
    $nodePath = Join-Path $tmp "vpn233-node.sh"
    [System.IO.File]::WriteAllText($nodePath, ($body -join "`n"), $utf8)
    & $BashExe -n $nodePath
    if ($LASTEXITCODE -ne 0) { throw "inner vpn233-node syntax error" }

    Write-Host "[syntax] OK"
} finally {
    Pop-Location
    Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
