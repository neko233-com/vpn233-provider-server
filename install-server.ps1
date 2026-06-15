param(
    [string]$InstallDir = $env:VPN233_INSTALL_DIR,
    [string]$RepoUrl = $env:VPN233_PROVIDER_REPO_URL,
    [string]$RepoBranch = $env:VPN233_PROVIDER_BRANCH,
    [string]$ListenAddr = $env:VPN233_LISTEN_ADDR,
    [int]$ListenPort = 0,
    [string]$AdminUser = $env:VPN233_ADMIN_USER,
    [string]$AdminPassword = $env:VPN233_ADMIN_PASSWORD,
    [string]$SubRepoUrl = $env:VPN233_SUB_REPO_URL,
    [string]$SubRepoPath = $env:VPN233_SUB_REPO_PATH,
    [string]$SubRepoBranch = $env:VPN233_SUB_REPO_BRANCH,
    [string]$VerifyToken = $env:VPN233_VERIFY_TOKEN,
    [string]$GoVersion = $env:VPN233_GO_VERSION
)

$ErrorActionPreference = "Stop"
if (-not $InstallDir) { $InstallDir = "C:\vpn233-provider-server" }
if (-not $RepoUrl) { $RepoUrl = "https://github.com/neko233-com/vpn233-provider-server.git" }
if (-not $RepoBranch) { $RepoBranch = "main" }
if (-not $ListenAddr) { $ListenAddr = "0.0.0.0" }
if ($ListenPort -le 0) { $ListenPort = 8080 }
if (-not $AdminUser) { $AdminUser = "root" }
if (-not $AdminPassword) { $AdminPassword = "root" }
if (-not $SubRepoUrl) { $SubRepoUrl = "https://github.com/neko233-com/vpn233-subscribe-server.git" }
if (-not $SubRepoPath) { $SubRepoPath = "vpn233-subscribe-server" }
if (-not $SubRepoBranch) { $SubRepoBranch = "main" }
if (-not $GoVersion) { $GoVersion = "1.26.0" }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "请使用管理员运行 PowerShell"
}

function Ensure-Go {
    $goVersionText = ""
    try {
        $goVersionText = (& go version) 2>$null
    } catch {
        $goVersionText = ""
    }
    if ($goVersionText -match "go1\.26") {
        return
    }
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id GoLang.Go --version $GoVersion --accept-source-agreements --accept-package-agreements --silent
        $env:Path += ";C:\Program Files\Go\bin"
        return
    }
    throw "未检测到 Go 1.26，且当前系统没有 winget，无法自动安装"
}

function Ensure-Git {
    if (Get-Command git -ErrorAction SilentlyContinue) {
        return
    }
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id Git.Git --accept-source-agreements --accept-package-agreements --silent
        $env:Path += ";C:\Program Files\Git\bin"
        return
    }
    throw "未检测到 git，且当前系统没有 winget，无法自动安装"
}

function Sync-Repo {
    if (Test-Path (Join-Path $InstallDir ".git")) {
        git -C $InstallDir fetch origin $RepoBranch
        git -C $InstallDir checkout $RepoBranch
        git -C $InstallDir reset --hard ("origin/" + $RepoBranch)
        return
    }
    if (Test-Path $InstallDir) {
        Remove-Item -Path $InstallDir -Recurse -Force
    }
    git clone --depth 1 -b $RepoBranch $RepoUrl $InstallDir
}

function Write-ConfigFile {
    $config = @{
        listen_addr = $ListenAddr
        listen_port = $ListenPort
        admin_user = $AdminUser
        admin_password = $AdminPassword
        default_data_dir = "/etc/vpn233"
        default_node_ip = ""
        default_port_base = 10000
        default_enable_bbr = $true
        default_use_mihomo = $true
        default_use_singbox = $true
        subscribe_repo_url = $SubRepoUrl
        subscribe_repo_path = $SubRepoPath
        subscribe_repo_branch = $SubRepoBranch
        subscribe_verify_token = $VerifyToken
    }
    $json = $config | ConvertTo-Json -Depth 4
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText((Join-Path $InstallDir "agent-config.json"), $json, $utf8NoBom)
}

function Build-App {
    Push-Location $InstallDir
    try {
        go build -o (Join-Path $InstallDir "vpn233-provider-server.exe") .
    } finally {
        Pop-Location
    }
}

function Install-Service {
    $exePath = Join-Path $InstallDir "vpn233-provider-server.exe"
    if (Get-Service -Name "vpn233-provider-server" -ErrorAction SilentlyContinue) {
        Stop-Service -Name "vpn233-provider-server" -Force -ErrorAction SilentlyContinue
        sc.exe delete "vpn233-provider-server" | Out-Null
        Start-Sleep -Seconds 2
    }
    New-Service -Name "vpn233-provider-server" -BinaryPathName ('"' + $exePath + '"') -DisplayName "vpn233-provider-server" -StartupType Automatic
    Start-Service -Name "vpn233-provider-server"
}

function Open-PanelPort {
    New-NetFirewallRule -DisplayName ("VPN233-Provider-" + $ListenPort) -Direction Inbound -Protocol TCP -Action Allow -LocalPort $ListenPort -Profile Any -ErrorAction SilentlyContinue | Out-Null
}

function Write-HelperScript {
    $helperPath = Join-Path $InstallDir "vpn233-provider.ps1"
    $helper = @"
param(
    [string]`$Token = ""
)
`$base = "http://127.0.0.1:$ListenPort"
switch (`$args[0]) {
    "status" { Get-Service -Name "vpn233-provider-server" }
    "restart" { Restart-Service -Name "vpn233-provider-server" -Force }
    "config" { Get-Content -Raw (Join-Path "$InstallDir" "agent-config.json") }
    "health" { Invoke-RestMethod -Uri "`$base/api/v1/health" -Method Get | Out-Host }
    "repo-status" {
        if (-not `$Token) { throw "usage: .\vpn233-provider.ps1 repo-status -Token <token>" }
        Invoke-RestMethod -Uri "`$base/api/v1/repo/status" -Method Get -Headers @{ Authorization = "Bearer `$Token" } | Out-Host
    }
    default {
        Write-Host "vpn233-provider.ps1 status"
        Write-Host "vpn233-provider.ps1 restart"
        Write-Host "vpn233-provider.ps1 config"
        Write-Host "vpn233-provider.ps1 health"
        Write-Host "vpn233-provider.ps1 repo-status -Token <token>"
    }
}
"@
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($helperPath, $helper, $utf8NoBom)
}

function Verify-Health {
    $healthUrl = "http://127.0.0.1:$ListenPort/api/v1/health"
    for ($i = 0; $i -lt 30; $i++) {
        try {
            $null = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 2
            return
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    throw "vpn233-provider-server 启动后未通过健康检查"
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Ensure-Go
Ensure-Git
Sync-Repo
Write-ConfigFile
Build-App
Install-Service
Open-PanelPort
Write-HelperScript
Verify-Health

Write-Host "========================================"
Write-Host "vpn233-provider-server 已安装"
Write-Host ("目录: " + $InstallDir)
Write-Host ("地址: http://{0}:{1}/" -f $ListenAddr, $ListenPort)
Write-Host ("账号: " + $AdminUser)
Write-Host ("密码: " + $AdminPassword)
Write-Host ("订阅仓库: " + $SubRepoUrl)
Write-Host ("订阅分支: " + $SubRepoBranch)
Write-Host ("管理脚本: " + (Join-Path $InstallDir "vpn233-provider.ps1"))
Write-Host "========================================"
