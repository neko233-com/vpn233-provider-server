# vpn233-provider-server

Go 1.26 版本的 agent-first VPN 管理端，面向 **provider-server** 与 **subscribe-server** 的一体化联调场景，提供：

- 浏览器后台管理（内置管理面板）
- `root / root` 默认管理员
- sing-box 可直接启动的多协议服务端模板
- mihomo 可直接运行的出站管理模板（`proxies / groups / rules`）
- `BBR`、防火墙放行等自动优化
- 裸脚本下载接口与 provider 管理面板自安装脚本
- 与订阅服务器联动的验收接口与仓库自动状态检查

> 说明：目标是“可落地的傻瓜化一键配置 + 订阅验收能力”，并不承担完整流量计费/计费系统。

## 运行行为（与订阅仓库联动）

服务启动时会读取 `agent-config.json` 并执行仓库状态检查：

- 当前目录是 root git 仓库时：不强制再次拉取
- 当前目录为子 git 仓库时：跳过对 `vpn233-subscribe-server` 的自动拉取
- 其他场景（非 git 或非 root）：尝试按配置克隆/更新 `vpn233-subscribe-server`

默认订阅仓库配置：

- `subscribe_repo_url`: `https://github.com/neko233-com/vpn233-subscribe-server.git`
- `subscribe_repo_path`: `vpn233-subscribe-server`
- `subscribe_repo_branch`: `main`

以上配置可在 `GET/POST /api/v1/config` 中查看和修改。

## 快速启动

```bash
go mod tidy
go test ./...
go run .
```

默认监听 `http://0.0.0.0:8080`，访问 `http://<ip>:8080/` 打开管理面板。

## 一键安装管理面板本身

Linux:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/neko233-com/vpn233-provider-server/main/install-server.sh)
```

Windows:

```powershell
Invoke-WebRequest -UseBasicParsing https://raw.githubusercontent.com/neko233-com/vpn233-provider-server/main/install-server.ps1 -OutFile install-server.ps1
powershell -ExecutionPolicy Bypass -File .\install-server.ps1
```

安装脚本会：

- 安装或检查 `Go 1.26`
- 拉取/更新 `vpn233-provider-server`
- 生成默认 `agent-config.json`
- 注册 `vpn233-provider-server` 常驻服务
- 自动放行管理面板端口
- 安装管理命令：Linux `vpn233-provider`，Windows `vpn233-provider.ps1`

## 登录

- 默认账号密码：`root / root`
- 登录成功后获取 `Bearer` token，用于调用管理接口

## API

- `POST /api/v1/login`
- `GET /api/v1/health`
- `GET /api/v1/protocols`
- `GET /api/v1/config`
- `POST /api/v1/config`
- `POST /api/v1/generate`
- `GET /api/v1/generate?format=sh|ps1`
- `GET /api/v1/generate.sh`
- `GET /api/v1/generate.ps1`
- `GET /api/v1/repo/status`（管理认证）
- `POST /api/v1/repo/sync`（管理认证）
- `GET /api/v1/subscribe/verify`（供订阅服务调用，支持 `token`）

`GET` 生成接口支持 query 参数：

- `node_name`
- `node_ip`
- `use_mihomo=true|false`
- `use_singbox=true|false`
- `enable_bbr=true|false`
- `port_base`
- `admin_password`
- `uuid`
- `password`
- `selected_protocols=singbox-vless-grpc,mihomo-vless-reality-grpc`

示例：

```bash
curl -sL -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8080/api/v1/generate?format=sh&node_name=edge-a&node_ip=203.0.113.8&use_singbox=true&use_mihomo=true&selected_protocols=singbox-vless-grpc,singbox-vless-reality-grpc,mihomo-vless-grpc" \
  -o edge-a-install.sh
```

## 订阅验收接口 `/api/v1/subscribe/verify`

订阅服务器可用此接口进行上线前联调检查：

```bash
curl "http://127.0.0.1:8080/api/v1/subscribe/verify?token=VERIFY_TOKEN"
```

返回字段：

- `ok`：`true/false`
- `service`：`vpn233-provider-server`
- `version`：当前 provider 版本字符串
- `git_root`：当前 git 工作区
- `protocols`：可用协议清单
- `repo_state`：订阅仓库地址/分支/路径/状态

## 生成脚本参数（`/api/v1/generate`）

```json
{
  "node_name": "vpn233-node",
  "node_ip": "auto",
  "use_mihomo": true,
  "use_singbox": true,
  "enable_bbr": true,
  "port_base": 10000,
  "admin_password": "xxx",
  "uuid": "optional",
  "password": "optional",
  "selected_protocols": [
    "singbox-vless",
    "singbox-vmess",
    "singbox-trojan",
    "singbox-shadowsocks"
  ]
}
```

返回：

```json
{
  "shell": "bash 内容",
  "ps1": "powershell 内容",
  "node": {
    "name": "...",
    "node_ip": "...",
    "uuid": "...",
    "password": "...",
    "ports": [
      {
        "id": "singbox-vless",
        "name": "VLESS",
        "core": "singbox",
        "port": 10000
      }
    ]
  }
}
```

## 核心行为

- 所有端口按 `port_base + N * 11` 自动分配
- sing-box 配置落盘：`/etc/vpn233/singbox/config.json`
- sing-box TLS 材料落盘：`/etc/vpn233/tls/server.crt` 与 `server.key`
- mihomo 配置落盘：`/etc/vpn233/mihomo/config.yaml`（可直接运行）
- 运行时元数据落盘：`/etc/vpn233/runtime/node-manifest.json` 与 `links.txt`
- 生成脚本支持 Linux `.sh` 与 Windows `.ps1`
- 端口与服务名默认做一键放行与基础优化
- 默认生成 `Reality` 公钥、`ShortID`、`gRPC service_name`、`WireGuard` 客户端材料
- 安装后自动注入管理命令：`vpn233-node`

## 当前协议覆盖

- sing-box：`VLESS TCP`、`VLESS gRPC`、`VLESS Reality`、`VLESS Reality gRPC`、`VMess TCP`、`VMess WS`、`Trojan`、`Trojan gRPC`、`Shadowsocks 2022`、`Hysteria2`、`TUIC`、`WireGuard`、`SOCKS5`、`HTTP`
- mihomo：`VLESS TCP`、`VLESS gRPC`、`VLESS Reality gRPC`、`VMess TCP`、`VMess WS`、`Trojan`、`Trojan gRPC`、`Shadowsocks 2022`、`Hysteria2`、`TUIC`、`WireGuard`

## 安装后管理命令

节点安装脚本会额外写入 `vpn233-node`：

- `vpn233-node status`
- `vpn233-node restart`
- `vpn233-node show-manifest`
- `vpn233-node show-links`
- `vpn233-node show-config`
- `vpn233-node enable-bt-block`
- `vpn233-node disable-bt-block`
- `vpn233-node add-block-domain example.com`
- `vpn233-node remove-block-domain example.com`

provider 管理面板安装脚本会额外写入：

- Linux: `vpn233-provider`
- Windows: `vpn233-provider.ps1`

## 自动化测试与验证

### 本地测试

```bash
go test ./...
```

### 一键验收脚本

项目提供 `scripts/verify.sh` 与 `scripts/verify.ps1`，用于 CI 或本地流水线：

- 运行单测
- 启动临时服务
- 访问 `/api/v1/health`
- 登录后台并读取 `/api/v1/repo/status`
- 调用 `/api/v1/subscribe/verify`
- 调用 `/api/v1/protocols`
- 清理服务进程

示例：

```bash
bash scripts/verify.sh
```

或（Windows）：

```powershell
powershell -File scripts/verify.ps1
```

## Agent First 操作面

### CLI

二进制现在自带命令行子命令，适合 agent、脚本和 CI 直接调用：

```bash
go run . health
go run . protocols
go run . config get
go run . config set --listen-port 18080 --default-use-singbox=true
go run . generate --format sh --node-name edge-01 --node-ip 203.0.113.10
```

支持的核心子命令：

- `serve`
- `health`
- `protocols`
- `config get`
- `config set`
- `generate`

### 本地 HTTP（免登录，仅回环）

为方便本机 agent first 编排，新增一组仅允许 `127.0.0.1` / `::1` 访问的本地接口；这些接口绕过后台登录鉴权，但不会对外网开放：

- `GET /api/v1/local/health`
- `GET /api/v1/local/protocols`
- `GET|POST /api/v1/local/config`
- `GET|POST /api/v1/local/generate`
- `GET /api/v1/local/generate.sh`
- `GET /api/v1/local/generate.ps1`
- `GET /api/v1/local/repo/status`
- `POST /api/v1/local/repo/sync`

示例：

```bash
curl http://127.0.0.1:8080/api/v1/local/protocols
curl "http://127.0.0.1:8080/api/v1/local/generate.sh?node_name=edge-01&node_ip=203.0.113.10&use_singbox=true&use_mihomo=false"
```

## 注意

- 脚本默认使用 GitHub Releases 最新版本，网络受限环境建议先配置镜像或固定版本后再发布
- 管理面板会优先读取环境变量 `VPN233_CONFIG_PATH`，否则尝试读取可执行文件同目录的 `agent-config.json`
- 上线前建议先在测试机执行端口连通与客户端联调
