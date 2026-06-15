param(
    [int]$Port = 18888,
    [string]$VerifyToken = "verify-token"
)

$ErrorActionPreference = "Stop"
$rootDir = Split-Path -Parent $PSScriptRoot
$workDir = Join-Path $env:TEMP ("vpn233-verify-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $workDir -Force | Out-Null

$cfgPath = Join-Path $workDir "agent-config.json"
$origCfg = Join-Path $rootDir "agent-config.json"
$bakCfg = Join-Path $workDir "agent-config.bak.json"

function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $freePort = ($listener.LocalEndpoint).Port
    $listener.Stop()
    return $freePort
}

if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
    $Port = Get-FreeTcpPort
}

$config = @{
    listen_addr = "127.0.0.1"
    listen_port = $Port
    admin_user = "root"
    admin_password = "root"
    default_data_dir = "/tmp/vpn233"
    default_node_ip = ""
    default_port_base = 10000
    default_enable_bbr = $true
    default_use_mihomo = $false
    default_use_singbox = $true
    subscribe_repo_url = "https://github.com/neko233-com/vpn233-subscribe-server.git"
    subscribe_repo_path = "vpn233-subscribe-server"
    subscribe_repo_branch = "main"
    subscribe_verify_token = $VerifyToken
}
$json = $config | ConvertTo-Json -Depth 3
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($cfgPath, $json, $utf8NoBom)

if (Test-Path -Path $origCfg) {
    Copy-Item -Path $origCfg -Destination $bakCfg -Force
}
Copy-Item -Path $cfgPath -Destination $origCfg -Force

$serverProcess = $null
try {
    Write-Host "[verify] run tests"
    Push-Location $rootDir
    go test ./...

    Write-Host "[verify] start provider server"
    $serverStdOut = Join-Path $workDir "server.stdout.log"
    $serverStdErr = Join-Path $workDir "server.stderr.log"
    $serverProcess = Start-Process -FilePath "go" -ArgumentList "run", "." -WorkingDirectory $rootDir -RedirectStandardOutput $serverStdOut -RedirectStandardError $serverStdErr -PassThru

    $base = "http://127.0.0.1:$Port"
    $healthUrl = "$base/api/v1/health"
    for ($i = 0; $i -lt 30; $i++) {
        try {
            $null = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 2
            break
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    if (-not (Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue)) {
        Write-Host "[verify] server stdout"
        Get-Content -Path $serverStdOut -ErrorAction SilentlyContinue | Out-Host
        Write-Host "[verify] server stderr"
        Get-Content -Path $serverStdErr -ErrorAction SilentlyContinue | Out-Host
        throw "provider server did not become healthy"
    }

    Write-Host "[verify] health"
    Invoke-WebRequest -Uri $healthUrl -UseBasicParsing | Select-Object -ExpandProperty Content | Out-Host

    Write-Host "[verify] login"
    $loginBody = @{
        username = "root"
        password = "root"
    } | ConvertTo-Json
    $loginResp = Invoke-RestMethod -Uri "$base/api/v1/login" -Method Post -ContentType "application/json" -Body $loginBody
    if (-not $loginResp.token) {
        throw "login failed"
    }

    Write-Host "[verify] repo status"
    $headers = @{ Authorization = "Bearer $($loginResp.token)" }
    Invoke-RestMethod -Uri "$base/api/v1/repo/status" -Method Get -Headers $headers | Out-Host

    Write-Host "[verify] protocols"
    Invoke-RestMethod -Uri "$base/api/v1/protocols" -Method Get | Out-Host

    Write-Host "[verify] subscribe verify"
    Invoke-RestMethod -Uri "$base/api/v1/subscribe/verify?token=$VerifyToken" -Method Get | Out-Host

    Write-Host "[verify] done"
} finally {
    if ($serverProcess -and -not $serverProcess.HasExited) {
        Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
        $serverProcess.WaitForExit(3000) | Out-Null
    }
    if (Test-Path -Path $bakCfg) {
        Move-Item -Path $bakCfg -Destination $origCfg -Force
    } else {
        Remove-Item -Path $origCfg -ErrorAction SilentlyContinue
    }
    Pop-Location
    Remove-Item -Path $workDir -Recurse -Force -ErrorAction SilentlyContinue
}
