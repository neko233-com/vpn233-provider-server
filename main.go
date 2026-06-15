package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
)

type ServerConfig struct {
	ListenAddr           string               `json:"listen_addr" yaml:"listen_addr"`
	ListenPort           int                  `json:"listen_port" yaml:"listen_port"`
	AdminUser            string               `json:"admin_user" yaml:"admin_user"`
	AdminPassword        string               `json:"admin_password" yaml:"admin_password"`
	DefaultDataDir       string               `json:"default_data_dir" yaml:"default_data_dir"`
	DefaultNodeIP        string               `json:"default_node_ip" yaml:"default_node_ip"`
	DefaultPortBase      int                  `json:"default_port_base" yaml:"default_port_base"`
	DefaultEnableBBR     bool                 `json:"default_enable_bbr" yaml:"default_enable_bbr"`
	DefaultUseMihomo     bool                 `json:"default_use_mihomo" yaml:"default_use_mihomo"`
	DefaultUseSingbox    bool                 `json:"default_use_singbox" yaml:"default_use_singbox"`
	SubscribeRepoURL     string               `json:"subscribe_repo_url" yaml:"subscribe_repo_url"`
	SubscribeRepoPath    string               `json:"subscribe_repo_path" yaml:"subscribe_repo_path"`
	SubscribeRepoBranch  string               `json:"subscribe_repo_branch" yaml:"subscribe_repo_branch"`
	SubscribeVerifyToken string               `json:"subscribe_verify_token" yaml:"subscribe_verify_token"`
	ProxySSS             ProxySSSGatewayConfig `json:"proxysss" yaml:"proxysss"`
	DNSAutomation        DNSAutomationConfig  `json:"dns_automation" yaml:"dns_automation"`
}

type ProtocolCatalog struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Core            string `json:"core"`
	Description     string `json:"description"`
	Default         bool   `json:"default"`
	DefaultDomain   bool   `json:"default_domain"`
	DefaultNoDomain bool   `json:"default_no_domain"`
	NeedsDomain     bool   `json:"needs_domain"`
	NeedsTLS        bool   `json:"needs_tls"`
	SupportsECH     bool   `json:"supports_ech"`
	SupportsReality bool   `json:"supports_reality"`
	SecurityLevel   string `json:"security_level"`
	RecommendedWhen string `json:"recommended_when"`
	Extensible      bool   `json:"extensible"`
	SubscribeTarget string `json:"subscribe_target,omitempty"`
}

type InstallRequest struct {
	NodeName          string   `json:"node_name"`
	NodeIP            string   `json:"node_ip"`
	UseMihomo         *bool    `json:"use_mihomo"`
	UseSingbox        *bool    `json:"use_singbox"`
	EnableBBR         *bool    `json:"enable_bbr"`
	EnableTCPFastOpen *bool    `json:"enable_tcp_fastopen"`
	EnableMPTCP       *bool    `json:"enable_mptcp"`
	EnableHardening   *bool    `json:"enable_hardening"`
	EnableFail2ban    *bool    `json:"enable_fail2ban"`
	EnableLogRotate   *bool    `json:"enable_logrotate"`
	EnableWatchdog    *bool    `json:"enable_watchdog"`
	EnableACME        *bool    `json:"enable_acme"`
	ACMEDomain        string   `json:"acme_domain"`
	ACMEEmail         string   `json:"acme_email"`
	TCPCongestion     string   `json:"tcp_congestion"`
	ConnLimit         int      `json:"conn_limit"`
	PortBase          int      `json:"port_base"`
	AdminPassword     string   `json:"admin_password"`
	UUID              string   `json:"uuid"`
	Password          string   `json:"password"`
	SelectedProtocols []string `json:"selected_protocols"`
}

type AuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ProtocolPort struct {
	ID   string
	Name string
	Core string
	Port int
}

type generateResult struct {
	Shell string `json:"shell"`
	PS1   string `json:"ps1"`
	Node  struct {
		Name                  string         `json:"name"`
		NodeIP                string         `json:"node_ip"`
		ServerName            string         `json:"server_name"`
		UUID                  string         `json:"uuid"`
		Password              string         `json:"password"`
		GRPCServiceName       string         `json:"grpc_service_name"`
		RealityPublicKey      string         `json:"reality_public_key"`
		RealityShortID        string         `json:"reality_short_id"`
		NekoTLSPublicName     string         `json:"nekotls_public_name,omitempty"`
		NekoTLSECHConfig      string         `json:"nekotls_ech_config,omitempty"`
		WireGuardClientKey    string         `json:"wireguard_client_private_key"`
		WireGuardPresharedKey string         `json:"wireguard_preshared_key"`
		WireGuardClientCIDR   string         `json:"wireguard_client_cidr"`
		MihomoDir             string         `json:"mihomo_dir"`
		SingBoxDir            string         `json:"singbox_dir"`
		Ports                 []ProtocolPort `json:"ports"`
		Links                 []string       `json:"links"`
	} `json:"node"`
	profile normalizedRequest
	mapping []ProtocolPort
}

type AppState struct {
	mu         sync.RWMutex
	cfgPath    string
	cfg        ServerConfig
	tokenMu    sync.Mutex
	tokenUntil map[string]time.Time
}

const dashboardHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>vpn233-agent</title>
  <style>
    :root {font-family: "Inter", "PingFang SC", "Microsoft YaHei", Arial, sans-serif;background:#0f172a;color:#e2e8f0;}
    body {margin:0;padding:0;}
    .wrap{max-width:1080px;margin:0 auto;padding:24px;}
    h1 {color:#93c5fd;}
    .card {background:rgba(15,23,42,0.82);border:1px solid #334155;border-radius:12px;padding:16px;margin-bottom:12px;}
    label{display:block;font-size:14px;margin:6px 0 2px;}
    input,select,button,textarea{width:100%;box-sizing:border-box;padding:10px;background:#0b1220;color:#e2e8f0;border:1px solid #334155;border-radius:8px;}
    button{cursor:pointer;font-weight:600;background:#2563eb;border-color:#2563eb;}
    button:hover{background:#1d4ed8;}
    .row{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
    .mono{font-family: ui-monospace, Consolas, monospace;font-size:12px;min-height:220px;}
    .protocols{display:grid;grid-template-columns:1fr 1fr;gap:8px;}
    .small{width:auto;padding:6px 12px;}
    .ok{color:#34d399;}
    .bad{color:#f87171;}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>VPN233 Agent（傻瓜式一键部署控制台）</h1>
    <div class="card">
      <h3>1) 登录</h3>
      <div class="row">
        <div><label>用户名</label><input id="u" value="root"></div>
        <div><label>密码</label><input id="p" type="password" value="root"></div>
      </div>
      <button id="loginBtn" class="small">登录</button>
      <p id="loginMsg"></p>
    </div>

    <div class="card" id="mainArea" style="display:none;">
      <h3>2) 节点安装配置</h3>
      <div class="row">
        <div><label>节点名</label><input id="nodeName"></div>
        <div><label>节点 IP（可留空，脚本自动探测）</label><input id="nodeIP" placeholder="auto"></div>
      </div>
      <div class="row">
        <div><label>起始端口</label><input id="portBase" type="number" value="10000"></div>
        <div><label>管理密码（用于生成 VLESS/Trojan 等）</label><input id="srvPwd" placeholder="auto"></div>
      </div>
      <div class="row">
        <div><label>是否安装 sing-box</label><select id="useSingbox"><option value="true" selected>是</option><option value="false">否</option></select></div>
        <div><label>是否安装 mihomo（示例模板）</label><select id="useMihomo"><option value="true">是</option><option value="false" selected>否</option></select></div>
      </div>
      <label><input type="checkbox" id="enableBBR" checked> 开启 BBR 与常用 TCP 优化</label>
      <h4>协议选择</h4>
      <p id="strategyHint" class="ok"></p>
      <div class="protocols" id="protocolList"></div>
      <button id="genBtn">生成一键脚本</button>
      <p id="genMsg"></p>
      <h4>bash 安装脚本</h4>
      <textarea id="shellOut" class="mono"></textarea>
      <button id="copySh" class="small">复制 bash 脚本</button>
      <h4>PowerShell 安装脚本</h4>
      <textarea id="psOut" class="mono"></textarea>
      <button id="copyPs" class="small">复制 PS 脚本</button>
    </div>
  </div>
<script>
const state = { token:"" };
const api = (path, opts={}) => {
  const headers = Object.assign({}, opts.headers||{}, {"Content-Type":"application/json"});
  if(state.token){ headers.Authorization = "Bearer " + state.token; }
  return fetch(path, Object.assign({}, opts, {headers}));
};
document.getElementById("loginBtn").onclick = async () => {
  const r = await api("/api/v1/login",{method:"POST", body: JSON.stringify({username:document.getElementById("u").value,password:document.getElementById("p").value})});
  const j = await r.json();
  if(!r.ok){document.getElementById("loginMsg").textContent = j.error || "登录失败"; return;}
  state.token = j.token;
  document.getElementById("loginMsg").innerHTML = "<span class='ok'>登录成功</span>";
  document.getElementById("mainArea").style.display = "block";
  loadProtocols();
  const c = await (await api("/api/v1/config")).json();
  if(c.node_name_default) document.getElementById("nodeName").value = c.node_name_default;
};

const loadProtocols = async () => {
  const list = document.getElementById("protocolList");
  list.innerHTML = "加载中...";
  const nodeIP = document.getElementById("nodeIP").value || "auto";
  const r = await api("/api/v1/protocols?node_ip=" + encodeURIComponent(nodeIP));
  const j = await r.json();
  if(!r.ok){list.textContent = "加载失败"; return;}
  list.innerHTML = "";
  const useDomainMode = (() => {
    const raw = (nodeIP || "").trim();
    if(!raw || raw === "auto"){ return false; }
    if(/^\d+\.\d+\.\d+\.\d+$/.test(raw)){ return false; }
    if(raw.includes(":") && /^[0-9a-fA-F:]+$/.test(raw)){ return false; }
    return raw.includes(".");
  })();
  document.getElementById("strategyHint").textContent = useDomainMode
    ? "检测到域名模式：旗舰默认 NekoTLS（ECH 隐藏 SNI），并保留 AnyTLS 兼容位。换成 ACME 正式证书安全等级最高。"
    : "检测到免域名模式：旗舰默认 NekoTLS（Reality 借壳）+ VLESS-Reality。傻瓜化一键落地。";
  j.forEach(p => {
    const box = document.createElement("label");
    const id = "p_"+p.id;
    const checked = p.default ? ' checked' : '';
    const meta = [];
    if (p.recommended_when) meta.push('推荐: ' + p.recommended_when);
    if (p.security_level) meta.push('安全: ' + p.security_level);
    if (p.needs_domain) meta.push('需域名');
    else meta.push('免域名可落地');
    if (p.supports_reality) meta.push('支持 Reality');
    if (p.supports_ech) meta.push('支持 ECH');
    if (p.extensible) meta.push('可扩展');
    if (p.subscribe_target) meta.push('订阅: ' + p.subscribe_target);
    box.innerHTML = '<input type="checkbox" id="' + id + '"' + checked + '> ' + p.name + ' <small>（' + p.core + '）</small><div style="font-size:12px;color:#94a3b8;margin-top:6px;">' + p.description + '</div><div style="font-size:11px;color:#64748b;margin-top:4px;">' + meta.join(' · ') + '</div>';
    box.style.border = "1px solid #334155";
    box.style.borderRadius = "8px";
    box.style.padding = "8px";
    list.appendChild(box);
  });
};
document.getElementById("nodeIP").addEventListener("change", loadProtocols);

document.getElementById("genBtn").onclick = async () => {
  const checked = [];
  document.querySelectorAll('#protocolList input[type="checkbox"]').forEach(el => {
    if(el.checked){ checked.push(el.id.replace("p_","")); }
  });
  const req = {
    node_name: document.getElementById("nodeName").value || "vpn233-node",
    node_ip: document.getElementById("nodeIP").value || "auto",
    use_singbox: document.getElementById("useSingbox").value === "true",
    use_mihomo: document.getElementById("useMihomo").value === "true",
    enable_bbr: document.getElementById("enableBBR").checked,
    port_base: Number(document.getElementById("portBase").value || 10000),
    admin_password: document.getElementById("srvPwd").value || "",
    selected_protocols: checked
  };
  const r = await api("/api/v1/generate",{method:"POST", body: JSON.stringify(req)});
  const j = await r.json();
  if(!r.ok){document.getElementById("genMsg").textContent = j.error || "生成失败"; return;}
  document.getElementById("shellOut").value = j.shell || "";
  document.getElementById("psOut").value = j.ps1 || "";
  document.getElementById("genMsg").innerHTML = "<span class='ok'>生成成功</span>";
};

document.getElementById("copySh").onclick = async () => {
  await navigator.clipboard.writeText(document.getElementById("shellOut").value);
  document.getElementById("genMsg").textContent = "bash 已复制";
};
document.getElementById("copyPs").onclick = async () => {
  await navigator.clipboard.writeText(document.getElementById("psOut").value);
  document.getElementById("genMsg").textContent = "ps1 已复制";
};
</script>
</body>
</html>`

var protocolCatalog = []ProtocolCatalog{
	{ID: "singbox-vless", Name: "VLESS-TCP", Core: "singbox", Description: "可直接启动的 VLESS TCP 入站", Default: true, DefaultNoDomain: false, DefaultDomain: false, NeedsDomain: false, NeedsTLS: false, SupportsReality: false, SupportsECH: false, SecurityLevel: "medium", RecommendedWhen: "兼容优先", Extensible: true},
	{ID: "singbox-vless-grpc", Name: "VLESS-gRPC", Core: "singbox", Description: "自签 TLS + gRPC 服务名模板", Default: true, DefaultNoDomain: false, DefaultDomain: false, NeedsDomain: false, NeedsTLS: true, SupportsReality: false, SupportsECH: false, SecurityLevel: "medium", RecommendedWhen: "需要 gRPC", Extensible: true},
	{ID: "singbox-vless-reality", Name: "VLESS-Reality", Core: "singbox", Description: "Reality TCP 入站，免域名可用", Default: true, DefaultNoDomain: true, DefaultDomain: false, NeedsDomain: false, NeedsTLS: false, SupportsReality: true, SupportsECH: false, SecurityLevel: "high", RecommendedWhen: "无域名默认", Extensible: true},
	{ID: "singbox-vless-reality-grpc", Name: "VLESS-Reality-gRPC", Core: "singbox", Description: "Reality + gRPC + 重放防护参数模板", Default: true, DefaultNoDomain: true, DefaultDomain: false, NeedsDomain: false, NeedsTLS: false, SupportsReality: true, SupportsECH: false, SecurityLevel: "high", RecommendedWhen: "无域名 + gRPC", Extensible: true},
	{ID: "singbox-anytls", Name: "AnyTLS", Core: "singbox", Description: "AnyTLS 入站模板，域名模式优先推荐", Default: false, DefaultNoDomain: false, DefaultDomain: true, NeedsDomain: false, NeedsTLS: true, SupportsReality: false, SupportsECH: false, SecurityLevel: "high-with-real-cert", RecommendedWhen: "有域名默认", Extensible: true},
	{ID: "singbox-nekotls", Name: "NekoTLS", Core: "singbox", Description: "neko233 自研 NekoTLS（AnyTLS 外层 + ECH/Reality 伪装）；sing-box 以原生 anytls 入站直接落地", Default: true, DefaultNoDomain: true, DefaultDomain: true, NeedsDomain: false, NeedsTLS: true, SupportsReality: true, SupportsECH: true, SecurityLevel: "high", RecommendedWhen: "旗舰默认：域名走 ECH，免域名走 Reality", Extensible: true, SubscribeTarget: "clash-meta-nekotls"},
	{ID: "singbox-vmess", Name: "VMess-TCP", Core: "singbox", Description: "标准 VMess TCP 入站", Default: false, DefaultNoDomain: false, DefaultDomain: false, NeedsDomain: false, NeedsTLS: false, SupportsReality: false, SupportsECH: false, SecurityLevel: "medium", RecommendedWhen: "兼容旧客户端", Extensible: true},
	{ID: "singbox-vmess-ws", Name: "VMess-WS", Core: "singbox", Description: "WS + TLS 入站模板", Default: false, DefaultNoDomain: false, DefaultDomain: false, NeedsDomain: false, NeedsTLS: true, SupportsReality: false, SupportsECH: false, SecurityLevel: "medium", RecommendedWhen: "WS 兼容场景", Extensible: true},
	{ID: "singbox-trojan", Name: "Trojan", Core: "singbox", Description: "Trojan TLS 入站模板", Default: true, DefaultNoDomain: false, DefaultDomain: true, NeedsDomain: false, NeedsTLS: true, SupportsReality: false, SupportsECH: false, SecurityLevel: "high-with-real-cert", RecommendedWhen: "域名兼容补位", Extensible: true},
	{ID: "singbox-trojan-grpc", Name: "Trojan-gRPC", Core: "singbox", Description: "Trojan + gRPC 入站模板", Default: false, DefaultNoDomain: false, DefaultDomain: false, NeedsDomain: false, NeedsTLS: true, SupportsReality: false, SupportsECH: false, SecurityLevel: "high-with-real-cert", RecommendedWhen: "Trojan + gRPC", Extensible: true},
	{ID: "singbox-shadowsocks", Name: "Shadowsocks", Core: "singbox", Description: "Shadowsocks 2022 直出模板", Default: true, DefaultNoDomain: false, DefaultDomain: true, NeedsDomain: false, NeedsTLS: false, SupportsReality: false, SupportsECH: false, SecurityLevel: "medium", RecommendedWhen: "备用协议", Extensible: true},
	{ID: "singbox-hysteria2", Name: "Hysteria2", Core: "singbox", Description: "QUIC/Hysteria2 自签证书模板", Default: false, DefaultNoDomain: false, DefaultDomain: false, NeedsDomain: false, NeedsTLS: true, SupportsReality: false, SupportsECH: false, SecurityLevel: "medium", RecommendedWhen: "高延迟链路", Extensible: true},
	{ID: "singbox-tuic", Name: "TUIC", Core: "singbox", Description: "TUIC + BBR 模板", Default: false, DefaultNoDomain: false, DefaultDomain: false, NeedsDomain: false, NeedsTLS: true, SupportsReality: false, SupportsECH: false, SecurityLevel: "medium", RecommendedWhen: "UDP 优先", Extensible: true},
	{ID: "singbox-wireguard", Name: "WireGuard", Core: "singbox", Description: "WireGuard 服务端模板", Default: false, DefaultNoDomain: false, DefaultDomain: false, NeedsDomain: false, NeedsTLS: false, SupportsReality: false, SupportsECH: false, SecurityLevel: "high", RecommendedWhen: "原生隧道", Extensible: true},
	{ID: "singbox-socks", Name: "SOCKS5", Core: "singbox", Description: "带密码的 SOCKS5 入站", Default: false, DefaultNoDomain: false, DefaultDomain: false, NeedsDomain: false, NeedsTLS: false, SupportsReality: false, SupportsECH: false, SecurityLevel: "low", RecommendedWhen: "内网调试", Extensible: true},
	{ID: "singbox-http", Name: "HTTP", Core: "singbox", Description: "带密码的 HTTP CONNECT 入站", Default: false, DefaultNoDomain: false, DefaultDomain: false, NeedsDomain: false, NeedsTLS: false, SupportsReality: false, SupportsECH: false, SecurityLevel: "low", RecommendedWhen: "兼容调试", Extensible: true},
	{ID: "mihomo-vless", Name: "Mihomo-VLESS", Core: "mihomo", Description: "VLESS TCP 出站管理模板", Default: true, DefaultNoDomain: false, DefaultDomain: false, NeedsDomain: false, NeedsTLS: false, SupportsReality: false, SupportsECH: false, SecurityLevel: "medium", RecommendedWhen: "兼容优先", Extensible: true},
	{ID: "mihomo-vless-grpc", Name: "Mihomo-VLESS-gRPC", Core: "mihomo", Description: "VLESS gRPC 出站模板", Default: true, DefaultNoDomain: false, DefaultDomain: false, NeedsDomain: false, NeedsTLS: true, SupportsReality: false, SupportsECH: false, SecurityLevel: "medium", RecommendedWhen: "需要 gRPC", Extensible: true},
	{ID: "mihomo-vless-reality-grpc", Name: "Mihomo-VLESS-Reality-gRPC", Core: "mihomo", Description: "Reality + gRPC 出站模板", Default: true, DefaultNoDomain: true, DefaultDomain: false, NeedsDomain: false, NeedsTLS: false, SupportsReality: true, SupportsECH: false, SecurityLevel: "high", RecommendedWhen: "无域名默认", Extensible: true},
	{ID: "mihomo-anytls", Name: "Mihomo-AnyTLS", Core: "mihomo", Description: "AnyTLS 出站模板，支持 ECH，域名模式推荐", Default: false, DefaultNoDomain: false, DefaultDomain: true, NeedsDomain: false, NeedsTLS: true, SupportsReality: false, SupportsECH: true, SecurityLevel: "high-with-real-cert", RecommendedWhen: "有域名默认", Extensible: true},
	{ID: "mihomo-nekotls", Name: "Mihomo-NekoTLS", Core: "mihomo", Description: "NekoTLS 原生出站（需 mihomo fork，type: nekotls）：统一 uTLS 指纹 + ECH + Reality", Default: true, DefaultNoDomain: true, DefaultDomain: true, NeedsDomain: false, NeedsTLS: true, SupportsReality: true, SupportsECH: true, SecurityLevel: "high", RecommendedWhen: "旗舰默认（Clash/mihomo 原生）", Extensible: true, SubscribeTarget: "clash-meta-nekotls"},
	{ID: "mihomo-vmess", Name: "Mihomo-VMess", Core: "mihomo", Description: "VMess TCP 出站模板", Default: false, DefaultNoDomain: false, DefaultDomain: false, NeedsDomain: false, NeedsTLS: false, SupportsReality: false, SupportsECH: false, SecurityLevel: "medium", RecommendedWhen: "兼容旧客户端", Extensible: true},
	{ID: "mihomo-vmess-ws", Name: "Mihomo-VMess-WS", Core: "mihomo", Description: "VMess WS 出站模板", Default: false, DefaultNoDomain: false, DefaultDomain: false, NeedsDomain: false, NeedsTLS: true, SupportsReality: false, SupportsECH: false, SecurityLevel: "medium", RecommendedWhen: "WS 兼容场景", Extensible: true},
	{ID: "mihomo-trojan", Name: "Mihomo-Trojan", Core: "mihomo", Description: "Trojan TLS 出站模板", Default: true, DefaultNoDomain: false, DefaultDomain: true, NeedsDomain: false, NeedsTLS: true, SupportsReality: false, SupportsECH: false, SecurityLevel: "high-with-real-cert", RecommendedWhen: "域名兼容补位", Extensible: true},
	{ID: "mihomo-trojan-grpc", Name: "Mihomo-Trojan-gRPC", Core: "mihomo", Description: "Trojan gRPC 出站模板", Default: false, DefaultNoDomain: false, DefaultDomain: false, NeedsDomain: false, NeedsTLS: true, SupportsReality: false, SupportsECH: false, SecurityLevel: "high-with-real-cert", RecommendedWhen: "Trojan + gRPC", Extensible: true},
	{ID: "mihomo-shadowsocks", Name: "Mihomo-Shadowsocks", Core: "mihomo", Description: "Shadowsocks 2022 出站模板", Default: true, DefaultNoDomain: false, DefaultDomain: true, NeedsDomain: false, NeedsTLS: false, SupportsReality: false, SupportsECH: false, SecurityLevel: "medium", RecommendedWhen: "备用协议", Extensible: true},
	{ID: "mihomo-hysteria2", Name: "Mihomo-Hysteria2", Core: "mihomo", Description: "Hysteria2 出站模板", Default: false, DefaultNoDomain: false, DefaultDomain: false, NeedsDomain: false, NeedsTLS: true, SupportsReality: false, SupportsECH: false, SecurityLevel: "medium", RecommendedWhen: "高延迟链路", Extensible: true},
	{ID: "mihomo-tuic", Name: "Mihomo-TUIC", Core: "mihomo", Description: "TUIC 出站模板", Default: false, DefaultNoDomain: false, DefaultDomain: false, NeedsDomain: false, NeedsTLS: true, SupportsReality: false, SupportsECH: false, SecurityLevel: "medium", RecommendedWhen: "UDP 优先", Extensible: true},
	{ID: "mihomo-wireguard", Name: "Mihomo-WireGuard", Core: "mihomo", Description: "WireGuard 出站模板", Default: false, DefaultNoDomain: false, DefaultDomain: false, NeedsDomain: false, NeedsTLS: false, SupportsReality: false, SupportsECH: false, SecurityLevel: "high", RecommendedWhen: "原生隧道", Extensible: true},
}

func main() {
	state, err := newAppState()
	if err != nil {
		log.Fatalf("init app state failed: %v", err)
	}
	if len(os.Args) > 1 && os.Args[1] != "serve" {
		if err := runCLI(state, os.Stdout, os.Args[1:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := runServer(state); err != nil {
		log.Fatal(err)
	}
}

func newAppState() (*AppState, error) {
	state := &AppState{
		cfgPath:    resolveConfigPath(),
		cfg:        defaultConfig(),
		tokenUntil: make(map[string]time.Time),
	}
	if err := state.loadConfig(); err != nil {
		return nil, err
	}
	state.cfg = applyServerConfigDefaults(state.cfg)
	return state, nil
}

func runServer(state *AppState) error {
	if result, ctx, err := ensureSubscribeRepoSync(state.snapshotConfig()); err != nil {
		log.Printf("subscribe repository check failed: %s status=%s error=%s", result.Status, result.Error, err)
	} else {
		log.Printf("subscribe repository status=%s action=%s git_root=%v submodule=%v", result.Status, result.Action, ctx.IsRootRepository, ctx.IsSubmodule)
	}
	cfg := state.snapshotConfig()
	addr := fmt.Sprintf("%s:%d", cfg.ListenAddr, cfg.ListenPort)
	log.Printf("vpn233-agent listening on %s", addr)
	return http.ListenAndServe(addr, buildMux(state))
}

func buildMux(state *AppState) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", state.dashboardHandler)
	mux.HandleFunc("/api/v1/health", state.healthHandler)
	mux.HandleFunc("/api/v1/login", state.loginHandler)
	mux.HandleFunc("/api/v1/protocols", state.protocolListHandler)
	mux.HandleFunc("/api/v1/config", state.configHandler)
	mux.HandleFunc("/api/v1/generate", state.auth(state.generateHandler))
	mux.HandleFunc("/api/v1/generate.sh", state.auth(state.generateAliasHandler("sh")))
	mux.HandleFunc("/api/v1/generate.ps1", state.auth(state.generateAliasHandler("ps1")))
	mux.HandleFunc("/api/v1/repo/status", state.auth(state.repoStatusHandler))
	mux.HandleFunc("/api/v1/repo/sync", state.auth(state.repoSyncHandler))
	mux.HandleFunc("/api/v1/subscribe/verify", state.subscribeVerifyHandler)
	mux.HandleFunc("/api/v1/subscribe/convert", state.subscribeConvertHandler)
	mux.HandleFunc("/api/v1/gateway/proxysss.yaml", state.auth(state.proxySSSGatewayYAMLHandler))
	mux.HandleFunc("/api/v1/gateway/register", state.auth(state.proxySSSRegisterHandler))

	mux.HandleFunc("/api/v1/local/health", state.localOnly(state.healthHandler))
	mux.HandleFunc("/api/v1/local/protocols", state.localOnly(state.protocolListHandler))
	mux.HandleFunc("/api/v1/local/config", state.localOnly(state.configHandler))
	mux.HandleFunc("/api/v1/local/generate", state.localOnly(state.generateHandler))
	mux.HandleFunc("/api/v1/local/generate.sh", state.localOnly(state.generateAliasHandler("sh")))
	mux.HandleFunc("/api/v1/local/generate.ps1", state.localOnly(state.generateAliasHandler("ps1")))
	mux.HandleFunc("/api/v1/local/repo/status", state.localOnly(state.repoStatusHandler))
	mux.HandleFunc("/api/v1/local/repo/sync", state.localOnly(state.repoSyncHandler))
	mux.HandleFunc("/api/v1/local/subscribe/convert", state.localOnly(state.subscribeConvertHandler))
	mux.HandleFunc("/api/v1/local/gateway/proxysss.yaml", state.localOnly(state.proxySSSGatewayYAMLHandler))
	mux.HandleFunc("/api/v1/local/gateway/register", state.localOnly(state.proxySSSRegisterHandler))
	return mux
}

func runCLI(state *AppState, stdout io.Writer, args []string) error {
	if len(args) == 0 {
		return runServer(state)
	}
	switch args[0] {
	case "help", "-h", "--help":
		printCLIUsage(stdout)
		return nil
	case "health":
		return runCLIHealth(state, stdout)
	case "protocols":
		return writeCLIJSON(stdout, map[string]any{"items": protocolCatalog})
	case "config":
		return runCLIConfig(state, stdout, args[1:])
	case "config-set":
		return runCLIConfigSet(state, stdout, args[1:])
	case "generate":
		return runCLIGenerate(state, stdout, args[1:])
	case "gateway-plan":
		return runCLIGatewayPlan(state, stdout)
	case "gateway-register":
		return runCLIGatewayRegister(state, stdout)
	default:
		return fmt.Errorf("unknown command %q\n\n%s", args[0], cliUsageText())
	}
}

func runCLIHealth(state *AppState, stdout io.Writer) error {
	cfg := state.snapshotConfig()
	return writeCLIJSON(stdout, map[string]any{
		"ok":          true,
		"config_path": state.cfgPath,
		"listen_addr": cfg.ListenAddr,
		"listen_port": cfg.ListenPort,
	})
}

func runCLIConfig(state *AppState, stdout io.Writer, args []string) error {
	if len(args) == 0 || args[0] == "get" {
		return writeCLIJSON(stdout, state.snapshotConfig())
	}
	if args[0] == "set" {
		return runCLIConfigSet(state, stdout, args[1:])
	}
	return fmt.Errorf("unknown config subcommand %q", args[0])
}

func runCLIConfigSet(state *AppState, stdout io.Writer, args []string) error {
	fs := flag.NewFlagSet("config-set", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	listenAddr := fs.String("listen-addr", "", "listen address")
	listenPort := fs.Int("listen-port", 0, "listen port")
	adminUser := fs.String("admin-user", "", "dashboard admin username")
	adminPassword := fs.String("admin-password", "", "dashboard admin password")
	defaultDataDir := fs.String("default-data-dir", "", "default data directory")
	defaultNodeIP := fs.String("default-node-ip", "", "default node IP")
	defaultPortBase := fs.Int("default-port-base", 0, "default port base")
	repoURL := fs.String("repo-url", "", "subscribe repo URL")
	repoPath := fs.String("repo-path", "", "subscribe repo path")
	repoBranch := fs.String("repo-branch", "", "subscribe repo branch")
	repoVerifyToken := fs.String("repo-verify-token", "", "subscribe verify token")
	proxySSSAdminURL := fs.String("proxysss-admin-url", "", "proxysss admin API URL")
	proxySSSBearerToken := fs.String("proxysss-bearer-token", "", "proxysss admin API bearer token")
	proxySSSProviderDomain := fs.String("proxysss-provider-domain", "", "public provider domain exposed by proxysss")
	proxySSSProviderSubdomain := fs.String("proxysss-provider-subdomain", "", "provider subdomain under dns base domain")
	proxySSSUpstream := fs.String("proxysss-upstream", "", "proxysss upstream URL for provider panel")
	dnsProvider := fs.String("dns-provider", "", "DNS provider for proxysss managed ACME")
	dnsToken := fs.String("dns-api-token", "", "DNS provider API token")
	dnsEmail := fs.String("dns-email", "", "DNS/ACME email")
	dnsBaseDomain := fs.String("dns-base-domain", "", "base domain for wildcard/provider routes")
	dnsChallenge := fs.String("dns-challenge", "", "ACME challenge type (dns01|http01|tls_alpn01)")

	var defaultEnableBBR optionalBool
	var defaultUseMihomo optionalBool
	var defaultUseSingbox optionalBool
	var proxySSSEnabled optionalBool
	var dnsEnabled optionalBool
	fs.Var(&defaultEnableBBR, "default-enable-bbr", "default BBR toggle")
	fs.Var(&defaultUseMihomo, "default-use-mihomo", "default Mihomo toggle")
	fs.Var(&defaultUseSingbox, "default-use-singbox", "default sing-box toggle")
	fs.Var(&proxySSSEnabled, "proxysss-enabled", "enable proxysss gateway integration")
	fs.Var(&dnsEnabled, "dns-enabled", "enable DNS-01 automation for proxysss")

	if err := fs.Parse(args); err != nil {
		return err
	}

	state.mu.Lock()
	if *listenAddr != "" {
		state.cfg.ListenAddr = *listenAddr
	}
	if *listenPort > 0 {
		state.cfg.ListenPort = *listenPort
	}
	if *adminUser != "" {
		state.cfg.AdminUser = *adminUser
	}
	if *adminPassword != "" {
		state.cfg.AdminPassword = *adminPassword
	}
	if *defaultDataDir != "" {
		state.cfg.DefaultDataDir = *defaultDataDir
	}
	if *defaultNodeIP != "" {
		state.cfg.DefaultNodeIP = *defaultNodeIP
	}
	if *defaultPortBase > 0 {
		state.cfg.DefaultPortBase = *defaultPortBase
	}
	if *repoURL != "" {
		state.cfg.SubscribeRepoURL = *repoURL
	}
	if *repoPath != "" {
		state.cfg.SubscribeRepoPath = *repoPath
	}
	if *repoBranch != "" {
		state.cfg.SubscribeRepoBranch = *repoBranch
	}
	if *repoVerifyToken != "" {
		state.cfg.SubscribeVerifyToken = *repoVerifyToken
	}
	if proxySSSEnabled.set {
		state.cfg.ProxySSS.Enabled = proxySSSEnabled.value
	}
	if *proxySSSAdminURL != "" {
		state.cfg.ProxySSS.AdminURL = *proxySSSAdminURL
	}
	if *proxySSSBearerToken != "" {
		state.cfg.ProxySSS.BearerToken = *proxySSSBearerToken
	}
	if *proxySSSProviderDomain != "" {
		state.cfg.ProxySSS.ProviderDomain = *proxySSSProviderDomain
	}
	if *proxySSSProviderSubdomain != "" {
		state.cfg.ProxySSS.ProviderSubdomain = *proxySSSProviderSubdomain
	}
	if *proxySSSUpstream != "" {
		state.cfg.ProxySSS.Upstream = *proxySSSUpstream
	}
	if dnsEnabled.set {
		state.cfg.DNSAutomation.Enabled = dnsEnabled.value
	}
	if *dnsProvider != "" {
		state.cfg.DNSAutomation.Provider = *dnsProvider
	}
	if *dnsToken != "" {
		state.cfg.DNSAutomation.APIToken = *dnsToken
	}
	if *dnsEmail != "" {
		state.cfg.DNSAutomation.Email = *dnsEmail
	}
	if *dnsBaseDomain != "" {
		state.cfg.DNSAutomation.BaseDomain = *dnsBaseDomain
	}
	if *dnsChallenge != "" {
		state.cfg.DNSAutomation.Challenge = *dnsChallenge
	}
	if defaultEnableBBR.set {
		state.cfg.DefaultEnableBBR = defaultEnableBBR.value
	}
	if defaultUseMihomo.set {
		state.cfg.DefaultUseMihomo = defaultUseMihomo.value
	}
	if defaultUseSingbox.set {
		state.cfg.DefaultUseSingbox = defaultUseSingbox.value
	}
	state.cfg = applyServerConfigDefaults(state.cfg)
	updated := state.cfg
	state.mu.Unlock()

	if err := state.saveConfig(); err != nil {
		return err
	}
	return writeCLIJSON(stdout, updated)
}

func runCLIGenerate(state *AppState, stdout io.Writer, args []string) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	format := fs.String("format", "json", "output format: json|sh|ps1")
	nodeName := fs.String("node-name", "", "node display name")
	nodeIP := fs.String("node-ip", "", "node public IP")
	adminPassword := fs.String("admin-password", "", "node panel password")
	uuid := fs.String("uuid", "", "custom UUID")
	password := fs.String("password", "", "custom password")
	protocols := fs.String("protocols", "", "comma separated protocol ids")
	portBase := fs.Int("port-base", 0, "base port")
	acmeDomain := fs.String("acme-domain", "", "ACME certificate domain")
	acmeEmail := fs.String("acme-email", "", "ACME registration email")
	tcpCongestion := fs.String("tcp-congestion", "", "TCP congestion control (bbr|cubic|...)")
	connLimit := fs.Int("conn-limit", 0, "open file/connection limit (nofile)")

	var useMihomo optionalBool
	var useSingbox optionalBool
	var enableBBR optionalBool
	var enableTCPFastOpen optionalBool
	var enableMPTCP optionalBool
	var enableHardening optionalBool
	var enableFail2ban optionalBool
	var enableLogRotate optionalBool
	var enableWatchdog optionalBool
	var enableACME optionalBool
	fs.Var(&useMihomo, "use-mihomo", "enable Mihomo outputs")
	fs.Var(&useSingbox, "use-singbox", "enable sing-box outputs")
	fs.Var(&enableBBR, "enable-bbr", "enable BBR optimization")
	fs.Var(&enableTCPFastOpen, "enable-tcp-fastopen", "enable TCP Fast Open")
	fs.Var(&enableMPTCP, "enable-mptcp", "enable Multipath TCP")
	fs.Var(&enableHardening, "enable-hardening", "enable kernel/security hardening")
	fs.Var(&enableFail2ban, "enable-fail2ban", "install fail2ban SSH protection")
	fs.Var(&enableLogRotate, "enable-logrotate", "install logrotate rules")
	fs.Var(&enableWatchdog, "enable-watchdog", "install self-healing watchdog")
	fs.Var(&enableACME, "enable-acme", "issue a real ACME certificate")

	if err := fs.Parse(args); err != nil {
		return err
	}

	req := InstallRequest{
		NodeName:      "vpn233-node",
		AdminPassword: state.snapshotConfig().AdminPassword,
	}
	if *nodeName != "" {
		req.NodeName = *nodeName
	}
	if *nodeIP == "" {
		return fmt.Errorf("--node-ip is required")
	}
	req.NodeIP = *nodeIP
	if *adminPassword != "" {
		req.AdminPassword = *adminPassword
	}
	if *uuid != "" {
		req.UUID = *uuid
	}
	if *password != "" {
		req.Password = *password
	}
	if *protocols != "" {
		req.SelectedProtocols = splitCSV(*protocols)
	}
	if *portBase > 0 {
		req.PortBase = *portBase
	}
	if useMihomo.set {
		req.UseMihomo = boolPtrValue(useMihomo.value)
	}
	if useSingbox.set {
		req.UseSingbox = boolPtrValue(useSingbox.value)
	}
	if enableBBR.set {
		req.EnableBBR = boolPtrValue(enableBBR.value)
	}
	if enableTCPFastOpen.set {
		req.EnableTCPFastOpen = boolPtrValue(enableTCPFastOpen.value)
	}
	if enableMPTCP.set {
		req.EnableMPTCP = boolPtrValue(enableMPTCP.value)
	}
	if enableHardening.set {
		req.EnableHardening = boolPtrValue(enableHardening.value)
	}
	if enableFail2ban.set {
		req.EnableFail2ban = boolPtrValue(enableFail2ban.value)
	}
	if enableLogRotate.set {
		req.EnableLogRotate = boolPtrValue(enableLogRotate.value)
	}
	if enableWatchdog.set {
		req.EnableWatchdog = boolPtrValue(enableWatchdog.value)
	}
	if enableACME.set {
		req.EnableACME = boolPtrValue(enableACME.value)
	}
	if *acmeDomain != "" {
		req.ACMEDomain = *acmeDomain
	}
	if *acmeEmail != "" {
		req.ACMEEmail = *acmeEmail
	}
	if *tcpCongestion != "" {
		req.TCPCongestion = *tcpCongestion
	}
	if *connLimit > 0 {
		req.ConnLimit = *connLimit
	}
	if len(req.SelectedProtocols) == 0 {
		req.SelectedProtocols = defaultProtocolIDsForStrategy(
			endpointStrategy(req.NodeIP),
			resolveEnabled(req.UseSingbox, state.snapshotConfig().DefaultUseSingbox),
			resolveEnabled(req.UseMihomo, state.snapshotConfig().DefaultUseMihomo),
		)
	}

	result, err := state.generateArtifacts(req)
	if err != nil {
		return err
	}

	switch strings.ToLower(*format) {
	case "json":
		return writeCLIJSON(stdout, result)
	case "sh":
		_, err = io.WriteString(stdout, result.Shell)
		return err
	case "ps1":
		_, err = io.WriteString(stdout, result.PS1)
		return err
	default:
		return fmt.Errorf("unsupported format %q", *format)
	}
}

func writeCLIJSON(stdout io.Writer, value any) error {
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func printCLIUsage(stdout io.Writer) {
	_, _ = io.WriteString(stdout, cliUsageText())
}

func cliUsageText() string {
	return strings.TrimSpace(`
vpn233-provider-server agent-first commands

Usage:
  vpn233-provider-server serve
  vpn233-provider-server health
  vpn233-provider-server protocols
  vpn233-provider-server config [get]
  vpn233-provider-server config set [flags]
  vpn233-provider-server config-set [flags]
  vpn233-provider-server generate --node-ip <ip> [flags]
	vpn233-provider-server gateway-plan
	vpn233-provider-server gateway-register

Examples:
  vpn233-provider-server protocols
  vpn233-provider-server config set --listen-port 18080 --default-use-singbox=true
  vpn233-provider-server generate --format sh --node-name edge-01 --node-ip 203.0.113.10
`) + "\n"
}

type optionalBool struct {
	set   bool
	value bool
}

func (b *optionalBool) String() string {
	if !b.set {
		return ""
	}
	return strconv.FormatBool(b.value)
}

func (b *optionalBool) Set(value string) error {
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return err
	}
	b.value = parsed
	b.set = true
	return nil
}

func (b *optionalBool) IsBoolFlag() bool {
	return true
}

func boolPtrValue(value bool) *bool {
	return &value
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	items := make([]string, 0)
	for _, item := range strings.Split(raw, ",") {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			items = append(items, trimmed)
		}
	}
	return items
}

func (a *AppState) localOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackRemote(r.RemoteAddr) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "local access only"})
			return
		}
		next(w, r)
	}
}

func isLoopbackRemote(remoteAddr string) bool {
	host := remoteAddr
	if parsedHost, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = parsedHost
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func resolveConfigPath() string {
	return resolveServerConfigPath()
}

func defaultConfig() ServerConfig {
	cfg := ServerConfig{
		ListenAddr:        "0.0.0.0",
		ListenPort:        8080,
		AdminUser:         "root",
		AdminPassword:     "root",
		DefaultDataDir:    "/etc/vpn233",
		DefaultNodeIP:     "",
		DefaultPortBase:   10000,
		DefaultEnableBBR:  true,
		DefaultUseMihomo:  false,
		DefaultUseSingbox: true,
		ProxySSS: ProxySSSGatewayConfig{
			AdminURL:          "http://127.0.0.1:7777",
			ProviderRouteName: "vpn233-provider-panel",
			ProviderSubdomain: "panel",
			Upstream:          "http://127.0.0.1:8080",
		},
		DNSAutomation: DNSAutomationConfig{
			Production:     true,
			Challenge:      "dns01",
			CreateWildcard: true,
		},
	}
	return normalizeRepoDefaults(cfg)
}

func (a *AppState) loadConfig() error {
	next, migrated, err := loadServerConfig(a.cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			a.cfg = defaultConfig()
			return a.saveConfig()
		}
		return err
	}
	a.cfg = next
	if migrated {
		return a.saveConfig()
	}
	return nil
}

func (a *AppState) saveConfig() error {
	a.mu.RLock()
	payload := a.cfg
	a.mu.RUnlock()
	return saveServerConfig(a.cfgPath, payload)
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeText(w http.ResponseWriter, status int, data string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(data))
}

func (a *AppState) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(dashboardHTML))
}

func (a *AppState) healthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "time": time.Now().Format(time.RFC3339)})
}

func (a *AppState) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "only POST"})
		return
	}
	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request"})
		return
	}
	a.mu.RLock()
	cfg := a.cfg
	a.mu.RUnlock()
	if req.Username != cfg.AdminUser || req.Password != cfg.AdminPassword {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "bad credentials"})
		return
	}
	token := randomToken(32)
	a.tokenMu.Lock()
	a.tokenUntil[token] = time.Now().Add(24 * time.Hour)
	a.tokenMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "exp": time.Now().Add(24 * time.Hour).Format(time.RFC3339)})
}

func (a *AppState) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
		if token == "" {
			token = strings.TrimSpace(r.URL.Query().Get("token"))
		}
		if token == "" || !a.verifyToken(token) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (a *AppState) verifyToken(token string) bool {
	a.tokenMu.Lock()
	defer a.tokenMu.Unlock()
	exp, ok := a.tokenUntil[token]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(a.tokenUntil, token)
		return false
	}
	a.tokenUntil[token] = time.Now().Add(24 * time.Hour)
	return true
}

func (a *AppState) snapshotConfig() ServerConfig {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg
}

func endpointStrategy(raw string) string {
	host := strings.TrimSpace(raw)
	if host == "" || strings.EqualFold(host, "auto") {
		return "no_domain"
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return "no_domain"
	}
	if strings.Contains(host, ".") {
		return "domain"
	}
	return "no_domain"
}

func protocolCatalogForStrategy(strategy string) []ProtocolCatalog {
	out := make([]ProtocolCatalog, len(protocolCatalog))
	copy(out, protocolCatalog)
	for i := range out {
		switch strategy {
		case "domain":
			out[i].Default = out[i].DefaultDomain
		default:
			out[i].Default = out[i].DefaultNoDomain
		}
	}
	return out
}

func resolveEnabled(flag *bool, fallback bool) bool {
	if flag != nil {
		return *flag
	}
	return fallback
}

func defaultProtocolIDsForStrategy(strategy string, useSingbox, useMihomo bool) []string {
	out := make([]string, 0)
	for _, item := range protocolCatalogForStrategy(strategy) {
		if !item.Default {
			continue
		}
		if item.Core == "singbox" && !useSingbox {
			continue
		}
		if item.Core == "mihomo" && !useMihomo {
			continue
		}
		out = append(out, item.ID)
	}
	return out
}

func (a *AppState) protocolListHandler(w http.ResponseWriter, r *http.Request) {
	nodeIP := strings.TrimSpace(r.URL.Query().Get("node_ip"))
	if nodeIP == "" {
		nodeIP = strings.TrimSpace(r.URL.Query().Get("host"))
	}
	out := protocolCatalogForStrategy(endpointStrategy(nodeIP))
	sort.Slice(out, func(i, j int) bool {
		return out[i].Core < out[j].Core || (out[i].Core == out[j].Core && out[i].ID < out[j].ID)
	})
	writeJSON(w, http.StatusOK, out)
}

func (a *AppState) configHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.mu.RLock()
		defer a.mu.RUnlock()
		writeJSON(w, http.StatusOK, configResponse(a.cfg, a.cfgPath))
	case http.MethodPost:
		rawBody, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request"})
			return
		}
		var body ServerConfig
		if err := json.Unmarshal(rawBody, &body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request"})
			return
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(rawBody, &raw); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request"})
			return
		}
		a.mu.Lock()
		if body.ListenAddr != "" {
			a.cfg.ListenAddr = body.ListenAddr
		}
		if body.ListenPort > 0 {
			a.cfg.ListenPort = body.ListenPort
		}
		if body.AdminUser != "" {
			a.cfg.AdminUser = body.AdminUser
		}
		if body.AdminPassword != "" {
			a.cfg.AdminPassword = body.AdminPassword
		}
		if body.SubscribeRepoURL != "" {
			a.cfg.SubscribeRepoURL = body.SubscribeRepoURL
		}
		if body.SubscribeRepoPath != "" {
			a.cfg.SubscribeRepoPath = body.SubscribeRepoPath
		}
		if body.SubscribeRepoBranch != "" {
			a.cfg.SubscribeRepoBranch = body.SubscribeRepoBranch
		}
		if body.SubscribeVerifyToken != "" {
			a.cfg.SubscribeVerifyToken = body.SubscribeVerifyToken
		}
		if body.DefaultDataDir != "" {
			a.cfg.DefaultDataDir = body.DefaultDataDir
		}
		if body.DefaultNodeIP != "" {
			a.cfg.DefaultNodeIP = body.DefaultNodeIP
		}
		if body.DefaultPortBase > 0 {
			a.cfg.DefaultPortBase = body.DefaultPortBase
		}
		if _, ok := raw["proxysss"]; ok {
			a.cfg.ProxySSS = body.ProxySSS
		}
		if _, ok := raw["dns_automation"]; ok {
			a.cfg.DNSAutomation = body.DNSAutomation
		}
		if _, ok := raw["default_enable_bbr"]; ok {
			a.cfg.DefaultEnableBBR = body.DefaultEnableBBR
		}
		if _, ok := raw["default_use_mihomo"]; ok {
			a.cfg.DefaultUseMihomo = body.DefaultUseMihomo
		}
		if _, ok := raw["default_use_singbox"]; ok {
			a.cfg.DefaultUseSingbox = body.DefaultUseSingbox
		}
		a.cfg = applyServerConfigDefaults(a.cfg)
		a.mu.Unlock()
		if err := a.saveConfig(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "save failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

func (a *AppState) generateHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req InstallRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request body"})
			return
		}
		res, err := a.generateArtifacts(req)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	case http.MethodGet:
		a.generateRawArtifact(w, r, "")
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "only GET/POST"})
	}
}

func (a *AppState) generateAliasHandler(format string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "only GET"})
			return
		}
		a.generateRawArtifact(w, r, format)
	}
}

func (a *AppState) generateRawArtifact(w http.ResponseWriter, r *http.Request, forcedFormat string) {
	format := strings.ToLower(strings.TrimSpace(forcedFormat))
	if format == "" {
		format = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	}
	if format != "sh" && format != "ps1" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "format must be sh or ps1"})
		return
	}
	req, err := parseInstallRequestFromQuery(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	res, err := a.generateArtifacts(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	filename := sanitizeFileName(res.Node.Name)
	if format == "sh" {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-install.sh\"", filename))
		writeText(w, http.StatusOK, res.Shell)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-install.ps1\"", filename))
	writeText(w, http.StatusOK, res.PS1)
}

func (a *AppState) repoStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "only GET"})
		return
	}
	cfg := a.snapshotConfig()
	ctx, err := inspectGitContext(".")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error":  "inspect git context failed",
			"detail": err.Error(),
		})
		return
	}
	result, _, syncErr := ensureSubscribeRepoSync(cfg)
	resp := map[string]any{
		"repo":            result,
		"git_context":     ctx,
		"sync_required":   syncErr != nil && !ctx.IsSubmodule,
		"verify_endpoint": "/api/v1/subscribe/verify",
	}
	if syncErr != nil {
		resp["error"] = syncErr.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *AppState) repoSyncHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "only POST"})
		return
	}
	cfg := a.snapshotConfig()
	result, _, err := ensureSubscribeRepoSync(cfg)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":      "repo sync failed",
			"detail":     err.Error(),
			"repo_state": result,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "repo_state": result})
}

func (a *AppState) subscribeVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "only GET"})
		return
	}
	cfg := a.snapshotConfig()
	if cfg.SubscribeVerifyToken != "" {
		got := strings.TrimSpace(r.URL.Query().Get("token"))
		if got != cfg.SubscribeVerifyToken {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "subscribe token mismatch"})
			return
		}
	}
	ctx, err := inspectGitContext(".")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	result, _, syncErr := ensureSubscribeRepoSync(cfg)
	if syncErr != nil && !ctx.IsSubmodule {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":          false,
			"error":       syncErr.Error(),
			"repo_state":  result,
			"git_context": ctx,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                true,
		"service":           "vpn233-provider-server",
		"version":           "1.2.0",
		"git_root":          ctx.TopLevel,
		"config_path":       a.cfgPath,
		"config_format":     defaultServerConfigFile,
		"protocols":         protocolCatalog,
		"subscribe_targets": subscribeTargets(),
		"gateway_endpoints": []string{"/api/v1/gateway/proxysss.yaml", "/api/v1/gateway/register"},
		"repo_state": map[string]any{
			"path":   result.RepoPath,
			"url":    result.RepoURL,
			"branch": result.Branch,
			"status": result.Status,
		},
	})
}

func (a *AppState) generateArtifacts(req InstallRequest) (generateResult, error) {
	a.mu.RLock()
	cfg := a.cfg
	a.mu.RUnlock()
	if len(req.SelectedProtocols) == 0 {
		req.SelectedProtocols = defaultProtocolIDsForStrategy(
			endpointStrategy(req.NodeIP),
			resolveEnabled(req.UseSingbox, cfg.DefaultUseSingbox),
			resolveEnabled(req.UseMihomo, cfg.DefaultUseMihomo),
		)
	}

	profile, err := normalizeRequest(req, cfg)
	if err != nil {
		return generateResult{}, err
	}
	selected, err := resolveProtocols(expandSelectedProtocolIDs(profile.SelectedProtocols))
	if err != nil {
		return generateResult{}, err
	}

	mapping := make([]ProtocolPort, 0, len(selected))
	portByBinding := make(map[string]int)
	nextPort := profile.PortBase
	for i, p := range selected {
		_ = i
		bindingKey := protocolBindingKey(p.ID)
		port, ok := portByBinding[bindingKey]
		if !ok {
			port = nextPort
			portByBinding[bindingKey] = port
			nextPort += 11
		}
		mapping = append(mapping, ProtocolPort{
			ID:   p.ID,
			Name: p.Name,
			Core: p.Core,
			Port: port,
		})
	}
	profile.PortMap = mapping

	singCfg, err := buildSingBoxConfig(profile, mapping)
	if err != nil {
		return generateResult{}, err
	}
	mihomoCfg, err := buildMihomoTemplate(profile, mapping)
	if err != nil {
		return generateResult{}, err
	}

	shellCtx := map[string]any{
		"NodeName":                  profile.NodeName,
		"NodeIP":                    profile.NodeIP,
		"ServerName":                profile.ServerName,
		"RealityServer":             profile.RealityServer,
		"DataDir":                   profile.DataDir,
		"UseMihomo":                 profile.UseMihomo,
		"UseSingbox":                profile.UseSingbox,
		"EnableBBR":                 profile.EnableBBR,
		"EnableTCPFastOpen":         profile.EnableTCPFastOpen,
		"EnableMPTCP":               profile.EnableMPTCP,
		"EnableHardening":           profile.EnableHardening,
		"EnableFail2ban":            profile.EnableFail2ban,
		"EnableLogRotate":           profile.EnableLogRotate,
		"EnableWatchdog":            profile.EnableWatchdog,
		"EnableACME":                profile.EnableACME,
		"ACMEDomain":                profile.ACMEDomain,
		"ACMEEmail":                 profile.ACMEEmail,
		"TCPCongestion":             profile.TCPCongestion,
		"ConnLimit":                 profile.ConnLimit,
		"PortBase":                  profile.PortBase,
		"UUID":                      profile.UUID,
		"Password":                  profile.Password,
		"GRPCServiceName":           profile.GRPCServiceName,
		"RealityPublicKey":          profile.RealityPublicKey,
		"RealityShortID":            profile.RealityShortID,
		"WireGuardClientPrivateKey": profile.WireGuardClientPrivateKey,
		"WireGuardServerPublicKey":  profile.WireGuardServerPublicKey,
		"WireGuardPresharedKey":     profile.WireGuardPresharedKey,
		"WireGuardClientCIDR":       profile.WireGuardClientCIDR,
		"Ports":                     mapping,
		"PortsCSV":                  buildPortsCSV(mapping),
		"PortsJSON":                 buildPortsJSON(mapping),
		"SingBoxConfig":             singCfg,
		"MihomoConfig":              mihomoCfg,
		"TLSCertPEM":                profile.TLSCertPEM,
		"TLSKeyPEM":                 profile.TLSKeyPEM,
		"GeneratedAt":               time.Now().Format(time.RFC3339),
	}

	sh, err := renderTemplate(shellInstallTemplate, shellCtx)
	if err != nil {
		return generateResult{}, err
	}
	ps1, err := renderTemplate(ps1InstallTemplate, map[string]any{
		"NodeName":                  profile.NodeName,
		"NodeIP":                    profile.NodeIP,
		"ServerName":                profile.ServerName,
		"RealityServer":             profile.RealityServer,
		"DataDir":                   profile.DataDir,
		"UseMihomo":                 profile.UseMihomo,
		"UseSingbox":                profile.UseSingbox,
		"EnableBBR":                 profile.EnableBBR,
		"EnableTCPFastOpen":         profile.EnableTCPFastOpen,
		"EnableHardening":           profile.EnableHardening,
		"ConnLimit":                 profile.ConnLimit,
		"GRPCServiceName":           profile.GRPCServiceName,
		"RealityPublicKey":          profile.RealityPublicKey,
		"RealityShortID":            profile.RealityShortID,
		"WireGuardClientPrivateKey": profile.WireGuardClientPrivateKey,
		"WireGuardServerPublicKey":  profile.WireGuardServerPublicKey,
		"WireGuardPresharedKey":     profile.WireGuardPresharedKey,
		"WireGuardClientCIDR":       profile.WireGuardClientCIDR,
		"PortsCSV":                  buildPortsCSV(mapping),
		"PortsJSON":                 buildPortsJSON(mapping),
		"Password":                  profile.Password,
		"SingBoxConfig":             singCfg,
		"MihomoConfig":              mihomoCfg,
		"TLSCertPEM":                profile.TLSCertPEM,
		"TLSKeyPEM":                 profile.TLSKeyPEM,
		"GeneratedAt":               time.Now().Format(time.RFC3339),
	})
	if err != nil {
		return generateResult{}, err
	}

	var result generateResult
	result.Shell = sh
	result.PS1 = ps1
	result.Node.Name = profile.NodeName
	result.Node.NodeIP = profile.NodeIP
	result.Node.ServerName = profile.ServerName
	result.Node.UUID = profile.UUID
	result.Node.Password = profile.Password
	result.Node.GRPCServiceName = profile.GRPCServiceName
	result.Node.RealityPublicKey = profile.RealityPublicKey
	result.Node.RealityShortID = profile.RealityShortID
	result.Node.NekoTLSPublicName = profile.NekoTLSPublicName
	result.Node.NekoTLSECHConfig = profile.NekoTLSECHConfig
	result.Node.WireGuardClientKey = profile.WireGuardClientPrivateKey
	result.Node.WireGuardPresharedKey = profile.WireGuardPresharedKey
	result.Node.WireGuardClientCIDR = profile.WireGuardClientCIDR
	result.Node.MihomoDir = filepath.Join(profile.DataDir, "mihomo")
	result.Node.SingBoxDir = filepath.Join(profile.DataDir, "singbox")
	result.Node.Ports = mapping
	result.Node.Links = buildConnectionLinks(profile, mapping)
	result.profile = profile
	result.mapping = mapping
	return result, nil
}

type normalizedRequest struct {
	NodeName                  string
	NodeIP                    string
	ServerName                string
	DataDir                   string
	UseMihomo                 bool
	UseSingbox                bool
	EnableBBR                 bool
	PortBase                  int
	AdminPassword             string
	UUID                      string
	Password                  string
	GRPCServiceName           string
	RealityPrivateKey         string
	RealityPublicKey          string
	RealityShortID            string
	RealityServer             string
	TLSCertPEM                string
	TLSKeyPEM                 string
	WireGuardServerPrivateKey string
	WireGuardServerPublicKey  string
	WireGuardClientPrivateKey string
	WireGuardClientPublicKey  string
	WireGuardPresharedKey     string
	WireGuardServerCIDR       string
	WireGuardClientCIDR       string
	NekoTLSPublicName         string
	NekoTLSECHConfig          string
	EnableTCPFastOpen         bool
	EnableMPTCP               bool
	EnableHardening           bool
	EnableFail2ban            bool
	EnableLogRotate           bool
	EnableWatchdog            bool
	EnableACME                bool
	ACMEDomain                string
	ACMEEmail                 string
	TCPCongestion             string
	ConnLimit                 int
	SelectedProtocols         []string
	PortMap                   []ProtocolPort
}

func normalizeRequest(req InstallRequest, cfg ServerConfig) (normalizedRequest, error) {
	out := normalizedRequest{
		NodeName:            "vpn233-node",
		NodeIP:              cfg.DefaultNodeIP,
		DataDir:             strings.TrimSpace(cfg.DefaultDataDir),
		PortBase:            cfg.DefaultPortBase,
		EnableBBR:           cfg.DefaultEnableBBR,
		UseMihomo:           cfg.DefaultUseMihomo,
		UseSingbox:          cfg.DefaultUseSingbox,
		GRPCServiceName:     "vpn233-grpc",
		RealityServer:       "www.cloudflare.com",
		WireGuardServerCIDR: "172.19.0.1/30",
		WireGuardClientCIDR: "172.19.0.2/32",
		EnableTCPFastOpen:   true,
		EnableHardening:     true,
		EnableFail2ban:      true,
		EnableLogRotate:     true,
		EnableWatchdog:      true,
		EnableMPTCP:         false,
		TCPCongestion:       "bbr",
		ConnLimit:           1048576,
	}
	if req.NodeName != "" {
		out.NodeName = req.NodeName
	}
	if req.NodeIP != "" && req.NodeIP != "auto" {
		out.NodeIP = req.NodeIP
	}
	if strings.TrimSpace(out.NodeIP) == "" || strings.EqualFold(strings.TrimSpace(out.NodeIP), "auto") {
		out.NodeIP = "127.0.0.1"
	}
	if req.PortBase > 0 {
		out.PortBase = req.PortBase
	}
	if req.UseMihomo != nil {
		out.UseMihomo = *req.UseMihomo
	}
	if req.UseSingbox != nil {
		out.UseSingbox = *req.UseSingbox
	}
	if req.EnableBBR != nil {
		out.EnableBBR = *req.EnableBBR
	}
	if req.EnableTCPFastOpen != nil {
		out.EnableTCPFastOpen = *req.EnableTCPFastOpen
	}
	if req.EnableMPTCP != nil {
		out.EnableMPTCP = *req.EnableMPTCP
	}
	if req.EnableHardening != nil {
		out.EnableHardening = *req.EnableHardening
	}
	if req.EnableFail2ban != nil {
		out.EnableFail2ban = *req.EnableFail2ban
	}
	if req.EnableLogRotate != nil {
		out.EnableLogRotate = *req.EnableLogRotate
	}
	if req.EnableWatchdog != nil {
		out.EnableWatchdog = *req.EnableWatchdog
	}
	if strings.TrimSpace(req.TCPCongestion) != "" {
		out.TCPCongestion = strings.ToLower(strings.TrimSpace(req.TCPCongestion))
	}
	if req.ConnLimit > 0 {
		out.ConnLimit = req.ConnLimit
	}
	out.ACMEDomain = strings.TrimSpace(req.ACMEDomain)
	out.ACMEEmail = strings.TrimSpace(req.ACMEEmail)
	if req.EnableACME != nil {
		out.EnableACME = *req.EnableACME
	} else {
		out.EnableACME = out.ACMEDomain != "" && endpointStrategy(out.NodeIP) == "domain"
	}
	out.AdminPassword = req.AdminPassword
	if req.AdminPassword != "" {
		out.Password = req.AdminPassword
	} else {
		out.Password = randomToken(16)
	}
	out.UUID = strings.TrimSpace(req.UUID)
	if out.UUID == "" {
		out.UUID = randomUUID()
	}
	if len(req.SelectedProtocols) > 0 {
		out.SelectedProtocols = req.SelectedProtocols
	} else {
		out.SelectedProtocols = defaultProtocolIDs()
	}
	out.ServerName = normalizeServerName(out.NodeIP)
	realityPrivate, realityPublic, err := generateRealityKeyPair()
	if err != nil {
		return normalizedRequest{}, err
	}
	out.RealityPrivateKey = realityPrivate
	out.RealityPublicKey = realityPublic
	out.RealityShortID = randomHex(8)
	tlsCert, tlsKey, err := generateSelfSignedCertificate(out.ServerName)
	if err != nil {
		return normalizedRequest{}, err
	}
	out.TLSCertPEM = tlsCert
	out.TLSKeyPEM = tlsKey
	wgServerPrivate, wgServerPublic, wgClientPrivate, wgClientPublic, wgPSK, err := generateWireGuardKeys()
	if err != nil {
		return normalizedRequest{}, err
	}
	out.WireGuardServerPrivateKey = wgServerPrivate
	out.WireGuardServerPublicKey = wgServerPublic
	out.WireGuardClientPrivateKey = wgClientPrivate
	out.WireGuardClientPublicKey = wgClientPublic
	out.WireGuardPresharedKey = wgPSK
	if endpointStrategy(out.NodeIP) == "domain" {
		out.NekoTLSPublicName = out.ServerName
	} else {
		out.NekoTLSPublicName = out.RealityServer
	}
	echConfig, err := generateNekoTLSECHConfig(out.NekoTLSPublicName)
	if err != nil {
		return normalizedRequest{}, err
	}
	out.NekoTLSECHConfig = echConfig
	return out, nil
}

func defaultProtocolIDs() []string {
	out := make([]string, 0, len(protocolCatalog))
	for _, p := range protocolCatalog {
		if p.Default {
			out = append(out, p.ID)
		}
	}
	if len(out) == 0 {
		out = append(out,
			"singbox-vless",
			"singbox-vless-grpc",
			"singbox-vless-reality-grpc",
			"singbox-trojan",
			"singbox-shadowsocks",
		)
	}
	return out
}

func resolveProtocols(selected []string) ([]ProtocolCatalog, error) {
	want := make(map[string]struct{}, len(selected))
	for _, id := range selected {
		want[id] = struct{}{}
	}
	out := make([]ProtocolCatalog, 0, len(want))
	for _, p := range protocolCatalog {
		if _, ok := want[p.ID]; ok {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid protocol selected")
	}
	allowed := make(map[string]struct{}, len(out))
	for _, p := range out {
		allowed[p.ID] = struct{}{}
	}
	for id := range want {
		if _, ok := allowed[id]; !ok {
			return nil, fmt.Errorf("unsupported protocol: %s", id)
		}
	}
	return out, nil
}

func expandSelectedProtocolIDs(selected []string) []string {
	if len(selected) == 0 {
		return selected
	}
	expanded := make([]string, 0, len(selected)*2)
	seen := make(map[string]struct{}, len(selected)*2)
	for _, id := range selected {
		if _, ok := seen[id]; !ok {
			expanded = append(expanded, id)
			seen[id] = struct{}{}
		}
		if pair, ok := mihomoToSingboxPair(id); ok {
			if _, exists := seen[pair]; !exists {
				expanded = append(expanded, pair)
				seen[pair] = struct{}{}
			}
		}
	}
	return expanded
}

func mihomoToSingboxPair(id string) (string, bool) {
	switch id {
	case "mihomo-vless":
		return "singbox-vless", true
	case "mihomo-vless-grpc":
		return "singbox-vless-grpc", true
	case "mihomo-vless-reality-grpc":
		return "singbox-vless-reality-grpc", true
	case "mihomo-anytls":
		return "singbox-anytls", true
	case "mihomo-nekotls":
		return "singbox-nekotls", true
	case "mihomo-vmess":
		return "singbox-vmess", true
	case "mihomo-vmess-ws":
		return "singbox-vmess-ws", true
	case "mihomo-trojan":
		return "singbox-trojan", true
	case "mihomo-trojan-grpc":
		return "singbox-trojan-grpc", true
	case "mihomo-shadowsocks":
		return "singbox-shadowsocks", true
	case "mihomo-hysteria2":
		return "singbox-hysteria2", true
	case "mihomo-tuic":
		return "singbox-tuic", true
	case "mihomo-wireguard":
		return "singbox-wireguard", true
	default:
		return "", false
	}
}

func protocolBindingKey(id string) string {
	id = strings.TrimPrefix(id, "singbox-")
	id = strings.TrimPrefix(id, "mihomo-")
	return id
}

func buildPortsCSV(ports []ProtocolPort) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("%d", p.Port)
	}
	return strings.Join(parts, ",")
}

func buildPortsJSON(ports []ProtocolPort) string {
	raw, err := json.Marshal(ports)
	if err != nil {
		return "[]"
	}
	return string(raw)
}

func buildConnectionLinks(req normalizedRequest, ports []ProtocolPort) []string {
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		if p.Core != "singbox" {
			continue
		}
		link := connectionLinkForProtocol(req, p)
		if link != "" {
			out = append(out, link)
		}
	}
	return out
}

func connectionLinkForProtocol(req normalizedRequest, p ProtocolPort) string {
	switch p.ID {
	case "singbox-vless":
		return fmt.Sprintf("vless://%s@%s:%d?security=none&type=tcp#%s", req.UUID, req.NodeIP, p.Port, p.Name)
	case "singbox-vless-grpc":
		return fmt.Sprintf("vless://%s@%s:%d?security=tls&sni=%s&type=grpc&serviceName=%s#%s", req.UUID, req.NodeIP, p.Port, req.ServerName, req.GRPCServiceName, p.Name)
	case "singbox-vless-reality":
		return fmt.Sprintf("vless://%s@%s:%d?security=reality&sni=%s&pbk=%s&sid=%s&type=tcp#%s", req.UUID, req.NodeIP, p.Port, req.RealityServer, req.RealityPublicKey, req.RealityShortID, p.Name)
	case "singbox-vless-reality-grpc":
		return fmt.Sprintf("vless://%s@%s:%d?security=reality&sni=%s&pbk=%s&sid=%s&type=grpc&serviceName=%s#%s", req.UUID, req.NodeIP, p.Port, req.RealityServer, req.RealityPublicKey, req.RealityShortID, req.GRPCServiceName, p.Name)
	case "singbox-anytls":
		return fmt.Sprintf("anytls://%s@%s:%d/?sni=%s&insecure=1#%s", req.Password, req.NodeIP, p.Port, req.ServerName, p.Name)
	case "singbox-nekotls":
		return nekotlsLink(req, p)
	case "singbox-vmess":
		return vmessLink(req.NodeIP, p.Port, req.UUID, "", "", false)
	case "singbox-vmess-ws":
		return vmessLink(req.NodeIP, p.Port, req.UUID, "/vpn233-vmess", req.ServerName, true)
	case "singbox-trojan":
		return fmt.Sprintf("trojan://%s@%s:%d?sni=%s#%s", req.Password, req.NodeIP, p.Port, req.ServerName, p.Name)
	case "singbox-trojan-grpc":
		return fmt.Sprintf("trojan://%s@%s:%d?sni=%s&type=grpc&serviceName=%s#%s", req.Password, req.NodeIP, p.Port, req.ServerName, req.GRPCServiceName, p.Name)
	case "singbox-shadowsocks":
		userInfo := base64.StdEncoding.EncodeToString([]byte("2022-blake3-chacha20-poly1305:" + req.Password))
		return fmt.Sprintf("ss://%s@%s:%d#%s", userInfo, req.NodeIP, p.Port, p.Name)
	case "singbox-hysteria2":
		return fmt.Sprintf("hysteria2://%s@%s:%d?sni=%s&insecure=1#%s", req.Password, req.NodeIP, p.Port, req.ServerName, p.Name)
	case "singbox-tuic":
		return fmt.Sprintf("tuic://%s:%s@%s:%d?sni=%s&congestion_control=bbr#%s", req.UUID, req.Password, req.NodeIP, p.Port, req.ServerName, p.Name)
	case "singbox-wireguard":
		return fmt.Sprintf("wireguard://%s@%s:%d?publickey=%s&presharedkey=%s&address=%s#%s", req.WireGuardClientPrivateKey, req.NodeIP, p.Port, req.WireGuardServerPublicKey, req.WireGuardPresharedKey, req.WireGuardClientCIDR, p.Name)
	case "singbox-socks":
		return fmt.Sprintf("socks5://vpn233:%s@%s:%d#%s", req.Password, req.NodeIP, p.Port, p.Name)
	case "singbox-http":
		return fmt.Sprintf("http://vpn233:%s@%s:%d#%s", req.Password, req.NodeIP, p.Port, p.Name)
	default:
		return ""
	}
}

func vmessLink(host string, port int, uuid, pathValue, serverName string, tlsEnabled bool) string {
	payload := map[string]string{
		"v":    "2",
		"ps":   "VMess",
		"add":  host,
		"port": strconv.Itoa(port),
		"id":   uuid,
		"aid":  "0",
		"scy":  "auto",
		"net":  "tcp",
		"type": "none",
		"host": "",
		"path": "",
		"tls":  "",
		"sni":  "",
	}
	if pathValue != "" {
		payload["net"] = "ws"
		payload["path"] = pathValue
		payload["host"] = serverName
	}
	if tlsEnabled {
		payload["tls"] = "tls"
		payload["sni"] = serverName
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(raw)
}

func buildSingBoxConfig(req normalizedRequest, ports []ProtocolPort) (string, error) {
	cfg := map[string]any{
		"log": map[string]any{
			"level":     "info",
			"timestamp": true,
		},
		"dns": map[string]any{
			"strategy": "prefer_ipv4",
			"servers": []any{
				map[string]any{"tag": "cloudflare", "address": "https://1.1.1.1/dns-query", "detour": "direct"},
				map[string]any{"tag": "alidns", "address": "223.5.5.5", "detour": "direct"},
			},
			"final": "cloudflare",
		},
		"inbounds": []any{},
		"outbounds": []any{
			map[string]any{
				"type": "dns",
				"tag":  "dns-out",
			},
			map[string]any{
				"type": "direct",
				"tag":  "direct",
			},
			map[string]any{
				"type": "block",
				"tag":  "block",
			},
		},
		"route": map[string]any{
			"auto_detect_interface": true,
			"final":                 "direct",
			"rules": []any{
				map[string]any{"protocol": "dns", "outbound": "dns-out"},
				map[string]any{"network": "udp", "port": 53, "outbound": "dns-out"},
			},
		},
	}
	inbounds := make([]any, 0)
	for _, p := range ports {
		if p.Core != "singbox" {
			continue
		}
		b, err := singBoxInbound(req, p)
		if err != nil {
			return "", err
		}
		inbounds = append(inbounds, b)
	}
	if len(inbounds) == 0 {
		inbounds = append(inbounds, singBoxInboundVLESS(18000, req.UUID))
	}
	cfg["inbounds"] = inbounds
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func singBoxInbound(req normalizedRequest, p ProtocolPort) (map[string]any, error) {
	switch p.ID {
	case "singbox-vless":
		return singBoxInboundVLESS(p.Port, req.UUID), nil
	case "singbox-vless-grpc":
		inbound := singBoxInboundVLESS(p.Port, req.UUID)
		inbound["tag"] = "vless-grpc-" + fmt.Sprintf("%d", p.Port)
		inbound["tls"] = singBoxTLSConfig(req, []string{"h2", "http/1.1"})
		inbound["transport"] = grpcTransport(req)
		return inbound, nil
	case "singbox-vless-reality":
		inbound := singBoxInboundVLESS(p.Port, req.UUID)
		inbound["tag"] = "vless-reality-" + fmt.Sprintf("%d", p.Port)
		inbound["tls"] = singBoxRealityConfig(req, []string{"h2", "http/1.1"})
		return inbound, nil
	case "singbox-vless-reality-grpc":
		inbound := singBoxInboundVLESS(p.Port, req.UUID)
		inbound["tag"] = "vless-reality-grpc-" + fmt.Sprintf("%d", p.Port)
		inbound["tls"] = singBoxRealityConfig(req, []string{"h2", "http/1.1"})
		inbound["transport"] = grpcTransport(req)
		return inbound, nil
	case "singbox-anytls":
		return map[string]any{
			"type":        "anytls",
			"tag":         "anytls-" + fmt.Sprintf("%d", p.Port),
			"listen":      "::",
			"listen_port": p.Port,
			"users": []any{
				map[string]any{
					"name":     "vpn233",
					"password": req.Password,
				},
			},
			"padding_scheme": []string{},
			"tls":            singBoxTLSConfig(req, []string{"h2", "http/1.1"}),
		}, nil
	case "singbox-nekotls":
		return singBoxNekoTLSInbound(req, p), nil
	case "singbox-vmess":
		return map[string]any{
			"type":        "vmess",
			"tag":         "vmess-" + fmt.Sprintf("%d", p.Port),
			"listen":      "::",
			"listen_port": p.Port,
			"users": []any{
				map[string]any{
					"uuid":    req.UUID,
					"alterId": 0,
				},
			},
			"proxy_protocol": false,
		}, nil
	case "singbox-vmess-ws":
		return map[string]any{
			"type":        "vmess",
			"tag":         "vmess-ws-" + fmt.Sprintf("%d", p.Port),
			"listen":      "::",
			"listen_port": p.Port,
			"users": []any{
				map[string]any{
					"uuid":    req.UUID,
					"alterId": 0,
				},
			},
			"tls":       singBoxTLSConfig(req, []string{"http/1.1"}),
			"transport": wsTransport("/vpn233-vmess", req.ServerName),
		}, nil
	case "singbox-trojan":
		return map[string]any{
			"type":        "trojan",
			"tag":         "trojan-" + fmt.Sprintf("%d", p.Port),
			"listen":      "::",
			"listen_port": p.Port,
			"users": []any{
				map[string]any{
					"name":     "admin",
					"password": req.Password,
				},
			},
			"tls": singBoxTLSConfig(req, []string{"h2", "http/1.1"}),
		}, nil
	case "singbox-trojan-grpc":
		return map[string]any{
			"type":        "trojan",
			"tag":         "trojan-grpc-" + fmt.Sprintf("%d", p.Port),
			"listen":      "::",
			"listen_port": p.Port,
			"users": []any{
				map[string]any{
					"name":     "admin",
					"password": req.Password,
				},
			},
			"tls":       singBoxTLSConfig(req, []string{"h2", "http/1.1"}),
			"transport": grpcTransport(req),
		}, nil
	case "singbox-shadowsocks":
		return map[string]any{
			"type":        "shadowsocks",
			"tag":         "ss-" + fmt.Sprintf("%d", p.Port),
			"listen":      "::",
			"listen_port": p.Port,
			"method":      "2022-blake3-chacha20-poly1305",
			"password":    req.Password,
		}, nil
	case "singbox-hysteria2":
		return map[string]any{
			"type":        "hysteria2",
			"tag":         "hysteria2-" + fmt.Sprintf("%d", p.Port),
			"listen":      "::",
			"listen_port": p.Port,
			"up_mbps":     100,
			"down_mbps":   1000,
			"users": []any{
				map[string]any{"password": req.Password},
			},
			"tls": singBoxTLSConfig(req, []string{"h3"}),
		}, nil
	case "singbox-tuic":
		return map[string]any{
			"type":        "tuic",
			"tag":         "tuic-" + fmt.Sprintf("%d", p.Port),
			"listen":      "::",
			"listen_port": p.Port,
			"users": []any{
				map[string]any{
					"uuid":     req.UUID,
					"password": req.Password,
				},
			},
			"congestion_control": "bbr",
			"zero_rtt_handshake": false,
			"tls":                singBoxTLSConfig(req, []string{"h3"}),
		}, nil
	case "singbox-wireguard":
		return map[string]any{
			"type":        "wireguard",
			"tag":         "wg-" + fmt.Sprintf("%d", p.Port),
			"listen_port": p.Port,
			"address":     []string{req.WireGuardServerCIDR},
			"private_key": req.WireGuardServerPrivateKey,
			"mtu":         1408,
			"peers": []any{
				map[string]any{
					"public_key":     req.WireGuardClientPublicKey,
					"pre_shared_key": req.WireGuardPresharedKey,
					"allowed_ips":    []string{req.WireGuardClientCIDR},
				},
			},
		}, nil
	case "singbox-socks":
		return map[string]any{
			"type":        "socks",
			"tag":         "socks-" + fmt.Sprintf("%d", p.Port),
			"listen":      "::",
			"listen_port": p.Port,
			"users": []any{
				map[string]any{"username": "vpn233", "password": req.Password},
			},
			"udp": true,
		}, nil
	case "singbox-http":
		return map[string]any{
			"type":        "http",
			"tag":         "http-" + fmt.Sprintf("%d", p.Port),
			"listen":      "::",
			"listen_port": p.Port,
			"users": []any{
				map[string]any{"username": "vpn233", "password": req.Password},
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported singbox protocol: %s", p.ID)
	}
}

func singBoxInboundVLESS(port int, uuid string) map[string]any {
	return map[string]any{
		"type":        "vless",
		"tag":         "vless-" + fmt.Sprintf("%d", port),
		"listen":      "::",
		"listen_port": port,
		"users": []any{
			map[string]any{
				"uuid": uuid,
				"flow": "xtls-rprx-vision",
			},
		},
		"tls": map[string]any{
			"enabled": false,
		},
	}
}

func singBoxTLSConfig(req normalizedRequest, alpn []string) map[string]any {
	cfg := map[string]any{
		"enabled":          true,
		"server_name":      req.ServerName,
		"certificate_path": toSlashPath(req.DataDir, "tls", "server.crt"),
		"key_path":         toSlashPath(req.DataDir, "tls", "server.key"),
	}
	if len(alpn) > 0 {
		cfg["alpn"] = alpn
	}
	return cfg
}

func singBoxRealityConfig(req normalizedRequest, alpn []string) map[string]any {
	cfg := map[string]any{
		"enabled":     true,
		"server_name": req.RealityServer,
		"reality": map[string]any{
			"enabled":             true,
			"private_key":         req.RealityPrivateKey,
			"short_id":            []string{req.RealityShortID},
			"max_time_difference": "10s",
			"handshake": map[string]any{
				"server":      req.RealityServer,
				"server_port": 443,
			},
		},
	}
	if len(alpn) > 0 {
		cfg["alpn"] = alpn
	}
	return cfg
}

func grpcTransport(req normalizedRequest) map[string]any {
	return map[string]any{
		"type":                  "grpc",
		"service_name":          req.GRPCServiceName,
		"idle_timeout":          "15s",
		"permit_without_stream": false,
	}
}

func wsTransport(pathValue, host string) map[string]any {
	return map[string]any{
		"type": "ws",
		"path": pathValue,
		"headers": map[string]any{
			"Host": host,
		},
	}
}

func buildMihomoTemplate(req normalizedRequest, ports []ProtocolPort) (string, error) {
	var b strings.Builder
	proxyNames := make([]string, 0)
	proxyBlocks := make([][]string, 0)
	for _, p := range ports {
		if p.Core != "mihomo" {
			continue
		}
		name := mihomoProxyName(p)
		lines, err := mihomoProxyLines(req, p, name)
		if err != nil {
			return "", err
		}
		proxyNames = append(proxyNames, name)
		proxyBlocks = append(proxyBlocks, lines)
	}

	_, _ = fmt.Fprintf(&b, "# generated: %s\n", req.NodeName)
	_, _ = fmt.Fprintln(&b, "# generated by vpn233-agent")
	_, _ = fmt.Fprintln(&b, "mixed-port: 7890")
	_, _ = fmt.Fprintln(&b, "allow-lan: true")
	_, _ = fmt.Fprintln(&b, "bind-address: 0.0.0.0")
	_, _ = fmt.Fprintln(&b, "ipv6: true")
	_, _ = fmt.Fprintln(&b, "mode: rule")
	_, _ = fmt.Fprintln(&b, "log-level: info")
	_, _ = fmt.Fprintln(&b, "external-controller: 127.0.0.1:9090")
	_, _ = fmt.Fprintln(&b, "find-process-mode: strict")
	_, _ = fmt.Fprintln(&b, "tcp-concurrent: true")
	_, _ = fmt.Fprintln(&b, "dns:")
	_, _ = fmt.Fprintln(&b, "  enable: true")
	_, _ = fmt.Fprintln(&b, "  ipv6: true")
	_, _ = fmt.Fprintln(&b, "  enhanced-mode: fake-ip")
	_, _ = fmt.Fprintln(&b, "  fake-ip-range: 198.18.0.1/16")
	_, _ = fmt.Fprintln(&b, "  nameserver:")
	_, _ = fmt.Fprintln(&b, "    - https://dns.alidns.com/dns-query")
	_, _ = fmt.Fprintln(&b, "    - https://cloudflare-dns.com/dns-query")
	_, _ = fmt.Fprintln(&b, "listeners:")
	_, _ = fmt.Fprintln(&b, "  - name: mixed-in")
	_, _ = fmt.Fprintln(&b, "    type: mixed")
	_, _ = fmt.Fprintln(&b, "    port: 7890")
	_, _ = fmt.Fprintln(&b, "    listen: 0.0.0.0")
	_, _ = fmt.Fprintln(&b, "proxies:")
	if len(proxyBlocks) == 0 {
		_, _ = fmt.Fprintln(&b, "  []")
	} else {
		for _, block := range proxyBlocks {
			for _, line := range block {
				_, _ = fmt.Fprintln(&b, line)
			}
		}
	}
	_, _ = fmt.Fprintln(&b, "proxy-groups:")
	_, _ = fmt.Fprintln(&b, "  - name: PROXY")
	_, _ = fmt.Fprintln(&b, "    type: select")
	_, _ = fmt.Fprintln(&b, "    proxies:")
	if len(proxyNames) == 0 {
		_, _ = fmt.Fprintln(&b, "      - DIRECT")
	} else {
		_, _ = fmt.Fprintln(&b, "      - AUTO")
		_, _ = fmt.Fprintln(&b, "      - DIRECT")
		for _, name := range proxyNames {
			_, _ = fmt.Fprintf(&b, "      - %s\n", name)
		}
		_, _ = fmt.Fprintln(&b, "  - name: AUTO")
		_, _ = fmt.Fprintln(&b, "    type: url-test")
		_, _ = fmt.Fprintln(&b, "    url: http://www.gstatic.com/generate_204")
		_, _ = fmt.Fprintln(&b, "    interval: 300")
		_, _ = fmt.Fprintln(&b, "    tolerance: 50")
		_, _ = fmt.Fprintln(&b, "    proxies:")
		for _, name := range proxyNames {
			_, _ = fmt.Fprintf(&b, "      - %s\n", name)
		}
	}
	_, _ = fmt.Fprintln(&b, "rules:")
	_, _ = fmt.Fprintln(&b, "  - DOMAIN-SUFFIX,local,DIRECT")
	_, _ = fmt.Fprintln(&b, "  - DOMAIN-KEYWORD,tracker,REJECT")
	_, _ = fmt.Fprintln(&b, "  - GEOIP,LAN,DIRECT,no-resolve")
	_, _ = fmt.Fprintln(&b, "  - GEOIP,CN,DIRECT,no-resolve")
	_, _ = fmt.Fprintln(&b, "  - MATCH,PROXY")
	return b.String(), nil
}

func mihomoProxyName(p ProtocolPort) string {
	base := strings.TrimPrefix(p.ID, "mihomo-")
	base = strings.ReplaceAll(base, "_", "-")
	return fmt.Sprintf("%s-%d", base, p.Port)
}

func mihomoProxyLines(req normalizedRequest, p ProtocolPort, name string) ([]string, error) {
	server := yamlQuote(req.NodeIP)
	switch p.ID {
	case "mihomo-vless":
		return []string{
			fmt.Sprintf("  - name: %s", yamlQuote(name)),
			"    type: vless",
			fmt.Sprintf("    server: %s", server),
			fmt.Sprintf("    port: %d", p.Port),
			fmt.Sprintf("    uuid: %s", yamlQuote(req.UUID)),
			"    udp: true",
			"    tls: false",
		}, nil
	case "mihomo-vless-grpc":
		return []string{
			fmt.Sprintf("  - name: %s", yamlQuote(name)),
			"    type: vless",
			fmt.Sprintf("    server: %s", server),
			fmt.Sprintf("    port: %d", p.Port),
			fmt.Sprintf("    uuid: %s", yamlQuote(req.UUID)),
			"    udp: true",
			"    tls: true",
			fmt.Sprintf("    servername: %s", yamlQuote(req.ServerName)),
			"    skip-cert-verify: true",
			"    network: grpc",
			"    grpc-opts:",
			fmt.Sprintf("      grpc-service-name: %s", yamlQuote(req.GRPCServiceName)),
		}, nil
	case "mihomo-vless-reality-grpc":
		return []string{
			fmt.Sprintf("  - name: %s", yamlQuote(name)),
			"    type: vless",
			fmt.Sprintf("    server: %s", server),
			fmt.Sprintf("    port: %d", p.Port),
			fmt.Sprintf("    uuid: %s", yamlQuote(req.UUID)),
			"    udp: true",
			"    tls: true",
			fmt.Sprintf("    servername: %s", yamlQuote(req.RealityServer)),
			"    client-fingerprint: chrome",
			"    network: grpc",
			"    grpc-opts:",
			fmt.Sprintf("      grpc-service-name: %s", yamlQuote(req.GRPCServiceName)),
			"    reality-opts:",
			fmt.Sprintf("      public-key: %s", yamlQuote(req.RealityPublicKey)),
			fmt.Sprintf("      short-id: %s", yamlQuote(req.RealityShortID)),
		}, nil
	case "mihomo-anytls":
		return []string{
			fmt.Sprintf("  - name: %s", yamlQuote(name)),
			"    type: anytls",
			fmt.Sprintf("    server: %s", server),
			fmt.Sprintf("    port: %d", p.Port),
			fmt.Sprintf("    password: %s", yamlQuote(req.Password)),
			"    udp: true",
			"    client-fingerprint: chrome",
			"    idle-session-check-interval: 30",
			"    idle-session-timeout: 30",
			"    min-idle-session: 0",
			fmt.Sprintf("    sni: %s", yamlQuote(req.ServerName)),
			"    skip-cert-verify: true",
		}, nil
	case "mihomo-nekotls":
		return renderNekoTLSYAMLLines(nekotlsProxyMap(req, p.Port, name)), nil
	case "mihomo-vmess":
		return []string{
			fmt.Sprintf("  - name: %s", yamlQuote(name)),
			"    type: vmess",
			fmt.Sprintf("    server: %s", server),
			fmt.Sprintf("    port: %d", p.Port),
			fmt.Sprintf("    uuid: %s", yamlQuote(req.UUID)),
			"    alterId: 0",
			"    cipher: auto",
			"    udp: true",
			"    tls: false",
		}, nil
	case "mihomo-vmess-ws":
		return []string{
			fmt.Sprintf("  - name: %s", yamlQuote(name)),
			"    type: vmess",
			fmt.Sprintf("    server: %s", server),
			fmt.Sprintf("    port: %d", p.Port),
			fmt.Sprintf("    uuid: %s", yamlQuote(req.UUID)),
			"    alterId: 0",
			"    cipher: auto",
			"    udp: true",
			"    tls: true",
			fmt.Sprintf("    servername: %s", yamlQuote(req.ServerName)),
			"    skip-cert-verify: true",
			"    network: ws",
			"    ws-opts:",
			"      path: /vpn233-vmess",
			"      headers:",
			fmt.Sprintf("        Host: %s", yamlQuote(req.ServerName)),
		}, nil
	case "mihomo-trojan":
		return []string{
			fmt.Sprintf("  - name: %s", yamlQuote(name)),
			"    type: trojan",
			fmt.Sprintf("    server: %s", server),
			fmt.Sprintf("    port: %d", p.Port),
			fmt.Sprintf("    password: %s", yamlQuote(req.Password)),
			"    udp: true",
			fmt.Sprintf("    sni: %s", yamlQuote(req.ServerName)),
			"    skip-cert-verify: true",
		}, nil
	case "mihomo-trojan-grpc":
		return []string{
			fmt.Sprintf("  - name: %s", yamlQuote(name)),
			"    type: trojan",
			fmt.Sprintf("    server: %s", server),
			fmt.Sprintf("    port: %d", p.Port),
			fmt.Sprintf("    password: %s", yamlQuote(req.Password)),
			"    udp: true",
			fmt.Sprintf("    sni: %s", yamlQuote(req.ServerName)),
			"    skip-cert-verify: true",
			"    network: grpc",
			"    grpc-opts:",
			fmt.Sprintf("      grpc-service-name: %s", yamlQuote(req.GRPCServiceName)),
		}, nil
	case "mihomo-shadowsocks":
		return []string{
			fmt.Sprintf("  - name: %s", yamlQuote(name)),
			"    type: ss",
			fmt.Sprintf("    server: %s", server),
			fmt.Sprintf("    port: %d", p.Port),
			"    cipher: 2022-blake3-chacha20-poly1305",
			fmt.Sprintf("    password: %s", yamlQuote(req.Password)),
			"    udp: true",
		}, nil
	case "mihomo-hysteria2":
		return []string{
			fmt.Sprintf("  - name: %s", yamlQuote(name)),
			"    type: hysteria2",
			fmt.Sprintf("    server: %s", server),
			fmt.Sprintf("    port: %d", p.Port),
			fmt.Sprintf("    password: %s", yamlQuote(req.Password)),
			fmt.Sprintf("    sni: %s", yamlQuote(req.ServerName)),
			"    skip-cert-verify: true",
			"    udp: true",
		}, nil
	case "mihomo-tuic":
		return []string{
			fmt.Sprintf("  - name: %s", yamlQuote(name)),
			"    type: tuic",
			fmt.Sprintf("    server: %s", server),
			fmt.Sprintf("    port: %d", p.Port),
			fmt.Sprintf("    uuid: %s", yamlQuote(req.UUID)),
			fmt.Sprintf("    password: %s", yamlQuote(req.Password)),
			"    udp: true",
			fmt.Sprintf("    sni: %s", yamlQuote(req.ServerName)),
			"    skip-cert-verify: true",
			"    congestion-controller: bbr",
		}, nil
	case "mihomo-wireguard":
		return []string{
			fmt.Sprintf("  - name: %s", yamlQuote(name)),
			"    type: wireguard",
			fmt.Sprintf("    server: %s", server),
			fmt.Sprintf("    port: %d", p.Port),
			fmt.Sprintf("    ip: %s", yamlQuote(req.WireGuardClientCIDR)),
			fmt.Sprintf("    private-key: %s", yamlQuote(req.WireGuardClientPrivateKey)),
			fmt.Sprintf("    public-key: %s", yamlQuote(req.WireGuardServerPublicKey)),
			fmt.Sprintf("    pre-shared-key: %s", yamlQuote(req.WireGuardPresharedKey)),
			"    udp: true",
			"    mtu: 1408",
		}, nil
	default:
		return nil, fmt.Errorf("unsupported mihomo protocol: %s", p.ID)
	}
}

func parseInstallRequestFromQuery(r *http.Request) (InstallRequest, error) {
	q := r.URL.Query()
	req := InstallRequest{
		NodeName:      strings.TrimSpace(q.Get("node_name")),
		NodeIP:        strings.TrimSpace(q.Get("node_ip")),
		AdminPassword: strings.TrimSpace(q.Get("admin_password")),
		UUID:          strings.TrimSpace(q.Get("uuid")),
		Password:      strings.TrimSpace(q.Get("password")),
	}
	if raw := strings.TrimSpace(q.Get("port_base")); raw != "" {
		portBase, err := strconv.Atoi(raw)
		if err != nil {
			return InstallRequest{}, fmt.Errorf("bad port_base")
		}
		req.PortBase = portBase
	}
	if v, ok, err := parseOptionalBoolQuery(q.Get("use_mihomo")); err != nil {
		return InstallRequest{}, fmt.Errorf("bad use_mihomo")
	} else if ok {
		req.UseMihomo = &v
	}
	if v, ok, err := parseOptionalBoolQuery(q.Get("use_singbox")); err != nil {
		return InstallRequest{}, fmt.Errorf("bad use_singbox")
	} else if ok {
		req.UseSingbox = &v
	}
	if v, ok, err := parseOptionalBoolQuery(q.Get("enable_bbr")); err != nil {
		return InstallRequest{}, fmt.Errorf("bad enable_bbr")
	} else if ok {
		req.EnableBBR = &v
	}
	boolFields := []struct {
		key   string
		field **bool
	}{
		{"enable_tcp_fastopen", &req.EnableTCPFastOpen},
		{"enable_mptcp", &req.EnableMPTCP},
		{"enable_hardening", &req.EnableHardening},
		{"enable_fail2ban", &req.EnableFail2ban},
		{"enable_logrotate", &req.EnableLogRotate},
		{"enable_watchdog", &req.EnableWatchdog},
		{"enable_acme", &req.EnableACME},
	}
	for _, bf := range boolFields {
		v, ok, err := parseOptionalBoolQuery(q.Get(bf.key))
		if err != nil {
			return InstallRequest{}, fmt.Errorf("bad %s", bf.key)
		}
		if ok {
			value := v
			*bf.field = &value
		}
	}
	req.ACMEDomain = strings.TrimSpace(q.Get("acme_domain"))
	req.ACMEEmail = strings.TrimSpace(q.Get("acme_email"))
	req.TCPCongestion = strings.TrimSpace(q.Get("tcp_congestion"))
	if raw := strings.TrimSpace(q.Get("conn_limit")); raw != "" {
		connLimit, err := strconv.Atoi(raw)
		if err != nil {
			return InstallRequest{}, fmt.Errorf("bad conn_limit")
		}
		req.ConnLimit = connLimit
	}
	rawProtocols := strings.TrimSpace(q.Get("selected_protocols"))
	if rawProtocols == "" {
		rawProtocols = strings.TrimSpace(q.Get("protocols"))
	}
	if rawProtocols != "" {
		for _, item := range strings.Split(rawProtocols, ",") {
			item = strings.TrimSpace(item)
			if item != "" {
				req.SelectedProtocols = append(req.SelectedProtocols, item)
			}
		}
	}
	return req, nil
}

func parseOptionalBoolQuery(raw string) (bool, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false, false, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, false, err
	}
	return v, true, nil
}

func sanitizeFileName(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "vpn233-node"
	}
	var b strings.Builder
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
			continue
		}
		b.WriteRune('-')
	}
	return strings.Trim(b.String(), "-")
}

func normalizeServerName(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return "vpn233.local"
	}
	if net.ParseIP(host) != nil {
		return host
	}
	host = strings.ToLower(host)
	host = strings.ReplaceAll(host, "_", "-")
	return host
}

func yamlQuote(raw string) string {
	return strconv.Quote(raw)
}

func renderTemplate(raw string, data any) (string, error) {
	t, err := template.New("t").Parse(raw)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := t.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

func randomToken(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if n <= 0 {
		n = 16
	}
	b := make([]byte, n)
	for i := range b {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		b[i] = alphabet[num.Int64()]
	}
	return string(b)
}

func randomUUID() string {
	b, err := readRandomBytes(16)
	if err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4],
		b[4:6],
		b[6:8],
		b[8:10],
		b[10:16],
	)
}

func randomHex(length int) string {
	if length <= 0 {
		length = 8
	}
	need := (length + 1) / 2
	b, err := readRandomBytes(need)
	if err != nil {
		return strings.Repeat("0", length)
	}
	return hex.EncodeToString(b)[:length]
}

func readRandomBytes(n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

func generateRealityKeyPair() (string, string, error) {
	curve := ecdh.X25519()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(privateKey.Bytes()), base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()), nil
}

func generateWireGuardKeys() (string, string, string, string, string, error) {
	curve := ecdh.X25519()
	serverPrivate, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", "", "", "", err
	}
	clientPrivate, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", "", "", "", err
	}
	psk, err := readRandomBytes(32)
	if err != nil {
		return "", "", "", "", "", err
	}
	return base64.StdEncoding.EncodeToString(serverPrivate.Bytes()),
		base64.StdEncoding.EncodeToString(serverPrivate.PublicKey().Bytes()),
		base64.StdEncoding.EncodeToString(clientPrivate.Bytes()),
		base64.StdEncoding.EncodeToString(clientPrivate.PublicKey().Bytes()),
		base64.StdEncoding.EncodeToString(psk),
		nil
}

func generateSelfSignedCertificate(host string) (string, string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serialBytes, err := readRandomBytes(16)
	if err != nil {
		return "", "", err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(0).SetBytes(serialBytes),
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"vpn233"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, privateKey.Public(), privateKey)
	if err != nil {
		return "", "", err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return string(certPEM), string(keyPEM), nil
}

func toSlashPath(parts ...string) string {
	return filepath.ToSlash(filepath.Join(parts...))
}

const shellInstallTemplate = `#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
UMASK=022
export DEBIAN_FRONTEND=noninteractive

NODE_NAME="{{.NodeName}}"
NODE_IP="{{.NodeIP}}"
SERVER_NAME="{{.ServerName}}"
REALITY_SERVER="{{.RealityServer}}"
DATA_DIR="{{.DataDir}}"
USE_MIHOMO="{{.UseMihomo}}"
USE_SINGBOX="{{.UseSingbox}}"
ENABLE_BBR="{{.EnableBBR}}"
ENABLE_TCP_FASTOPEN="{{.EnableTCPFastOpen}}"
ENABLE_MPTCP="{{.EnableMPTCP}}"
ENABLE_HARDENING="{{.EnableHardening}}"
ENABLE_FAIL2BAN="{{.EnableFail2ban}}"
ENABLE_LOGROTATE="{{.EnableLogRotate}}"
ENABLE_WATCHDOG="{{.EnableWatchdog}}"
ENABLE_ACME="{{.EnableACME}}"
ACME_DOMAIN="{{.ACMEDomain}}"
ACME_EMAIL="{{.ACMEEmail}}"
TCP_CONGESTION="{{.TCPCongestion}}"
CONN_LIMIT="{{.ConnLimit}}"
UUID="{{.UUID}}"
PASSWORD="{{.Password}}"
GRPC_SERVICE_NAME="{{.GRPCServiceName}}"
REALITY_PUBLIC_KEY="{{.RealityPublicKey}}"
REALITY_SHORT_ID="{{.RealityShortID}}"
WG_CLIENT_KEY="{{.WireGuardClientPrivateKey}}"
WG_SERVER_PUBLIC_KEY="{{.WireGuardServerPublicKey}}"
WG_PRESHARED_KEY="{{.WireGuardPresharedKey}}"
WG_CLIENT_CIDR="{{.WireGuardClientCIDR}}"
PORT_LIST="{{.PortsCSV}}"
PORTS_JSON='{{.PortsJSON}}'
GENERATED_AT="{{.GeneratedAt}}"
SINGBOX_CONFIG='{{.SingBoxConfig}}'
MIHOMO_CONFIG='{{.MihomoConfig}}'

if [[ "$EUID" -ne 0 ]]; then
  echo "请使用 root 身份执行"
  exit 1
fi

if command -v apt-get >/dev/null 2>&1; then
  export INSTALLER="apt-get"
  export PACKAGE_UPDATE="apt-get update -y"
  export PACKAGE_INSTALL="apt-get install -y"
elif command -v yum >/dev/null 2>&1; then
  export INSTALLER="yum"
  export PACKAGE_UPDATE="yum -y update"
  export PACKAGE_INSTALL="yum -y install"
elif command -v dnf >/dev/null 2>&1; then
  export INSTALLER="dnf"
  export PACKAGE_UPDATE="dnf -y update"
  export PACKAGE_INSTALL="dnf -y install"
else
  echo "当前系统不支持自动安装依赖"
fi

if command -v curl >/dev/null 2>&1; then
  :
else
  if [[ -n "${PACKAGE_INSTALL:-}" ]]; then
    ${PACKAGE_UPDATE} >/dev/null 2>&1 || true
    ${PACKAGE_INSTALL} -y curl tar gzip ca-certificates >/dev/null 2>&1
  fi
fi

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64)
    SINGBOX_ARCH="amd64"
    MIHOMO_ARCH="amd64"
    ;;
  aarch64|arm64)
    SINGBOX_ARCH="arm64"
    MIHOMO_ARCH="arm64"
    ;;
  *)
    echo "不支持的架构: $arch"
    exit 1
    ;;
esac

mkdir -p "$DATA_DIR/singbox" "$DATA_DIR/mihomo" "$DATA_DIR/tls" "/etc/systemd/system"

tune_performance() {
  if [[ "$ENABLE_BBR" != "true" ]]; then
    echo "跳过内核性能优化 (ENABLE_BBR=false)"
    return
  fi
  local cc="${TCP_CONGESTION:-bbr}"
  if [[ "$cc" == "bbr" ]]; then
    modprobe tcp_bbr 2>/dev/null || true
  fi
  local tfo=0
  if [[ "$ENABLE_TCP_FASTOPEN" == "true" ]]; then
    tfo=3
  fi
  cat >/etc/sysctl.d/99-vpn233.conf <<EOF
# vpn233 performance tuning ($GENERATED_AT)
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=${cc}
net.core.netdev_max_backlog=250000
net.core.netdev_budget=600
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.core.rmem_default=1048576
net.core.wmem_default=1048576
net.core.optmem_max=65536
net.core.somaxconn=65535
net.ipv4.tcp_rmem=4096 87380 134217728
net.ipv4.tcp_wmem=4096 65536 134217728
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
net.ipv4.tcp_adv_win_scale=2
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_keepalive_time=600
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_max_syn_backlog=65535
net.ipv4.tcp_max_tw_buckets=2000000
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fastopen=${tfo}
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
fs.file-max=2097152
fs.nr_open=2097152
net.core.netfilter.nf_conntrack_max=1048576
EOF
  if [[ "$ENABLE_MPTCP" == "true" ]]; then
    echo "net.mptcp.enabled=1" >>/etc/sysctl.d/99-vpn233.conf
  fi
  sysctl --system >/dev/null 2>&1 || true
  echo "已应用内核性能优化: congestion=${cc} tfo=${ENABLE_TCP_FASTOPEN} mptcp=${ENABLE_MPTCP}"
}

apply_resource_limits() {
  local limit="${CONN_LIMIT:-1048576}"
  mkdir -p /etc/security/limits.d
  cat >/etc/security/limits.d/99-vpn233.conf <<EOF
* soft nofile ${limit}
* hard nofile ${limit}
* soft nproc ${limit}
* hard nproc ${limit}
root soft nofile ${limit}
root hard nofile ${limit}
root soft nproc ${limit}
root hard nproc ${limit}
EOF
  if [[ -f /etc/pam.d/common-session ]] && ! grep -q 'pam_limits.so' /etc/pam.d/common-session; then
    echo "session required pam_limits.so" >>/etc/pam.d/common-session || true
  fi
  mkdir -p /etc/systemd/system.conf.d
  cat >/etc/systemd/system.conf.d/99-vpn233.conf <<EOF
[Manager]
DefaultLimitNOFILE=${limit}
DefaultLimitNPROC=${limit}
EOF
  command -v systemctl >/dev/null 2>&1 && systemctl daemon-reexec >/dev/null 2>&1 || true
  ulimit -n "${limit}" 2>/dev/null || true
  echo "已设置最大连接/文件句柄: ${limit}"
}

apply_security_hardening() {
  if [[ "$ENABLE_HARDENING" != "true" ]]; then
    return
  fi
  cat >/etc/sysctl.d/99-vpn233-security.conf <<'EOF'
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
EOF
  sysctl --system >/dev/null 2>&1 || true
  echo "已应用安全加固 sysctl"
}

install_fail2ban() {
  if [[ "$ENABLE_FAIL2BAN" != "true" ]]; then
    return
  fi
  if ! command -v fail2ban-server >/dev/null 2>&1; then
    if [[ -n "${PACKAGE_INSTALL:-}" ]]; then
      ${PACKAGE_INSTALL} fail2ban >/dev/null 2>&1 || { echo "fail2ban 安装失败，跳过"; return; }
    else
      echo "无包管理器，跳过 fail2ban"
      return
    fi
  fi
  mkdir -p /etc/fail2ban/jail.d
  cat >/etc/fail2ban/jail.d/vpn233.conf <<'EOF'
[sshd]
enabled = true
port = ssh
maxretry = 5
findtime = 600
bantime = 3600
EOF
  systemctl enable --now fail2ban >/dev/null 2>&1 || true
  echo "已启用 fail2ban SSH 防爆破"
}

install_logrotate() {
  if [[ "$ENABLE_LOGROTATE" != "true" ]]; then
    return
  fi
  mkdir -p /etc/logrotate.d
  cat >/etc/logrotate.d/vpn233 <<EOF
$DATA_DIR/runtime/*.log $DATA_DIR/singbox/*.log $DATA_DIR/mihomo/*.log {
  daily
  rotate 7
  compress
  delaycompress
  missingok
  notifempty
  copytruncate
}
EOF
  echo "已配置日志轮转 (保留 7 天)"
}

install_watchdog() {
  if [[ "$ENABLE_WATCHDOG" != "true" ]]; then
    return
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "无 systemd，跳过看门狗"
    return
  fi
  cat >/usr/local/bin/vpn233-watchdog <<'WD'
#!/usr/bin/env bash
for svc in vpn233-singbox vpn233-mihomo; do
  if systemctl list-unit-files | grep -q "${svc}.service"; then
    systemctl is-active --quiet "$svc" || systemctl restart "$svc"
  fi
done
WD
  chmod 755 /usr/local/bin/vpn233-watchdog
  cat >/etc/systemd/system/vpn233-watchdog.service <<'EOF'
[Unit]
Description=vpn233 self-healing watchdog
[Service]
Type=oneshot
ExecStart=/usr/local/bin/vpn233-watchdog
EOF
  cat >/etc/systemd/system/vpn233-watchdog.timer <<'EOF'
[Unit]
Description=vpn233 watchdog timer
[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
AccuracySec=10s
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now vpn233-watchdog.timer >/dev/null 2>&1 || true
  echo "已启用自愈看门狗 (每 2 分钟巡检)"
}

issue_acme_cert() {
  if [[ "$ENABLE_ACME" != "true" ]]; then
    return
  fi
  if [[ -z "$ACME_DOMAIN" ]]; then
    echo "ACME 已开启但未提供域名，跳过"
    return
  fi
  echo "申请 ACME 证书: $ACME_DOMAIN"
  command -v ufw >/dev/null 2>&1 && ufw allow 80/tcp >/dev/null 2>&1 || true
  command -v firewall-cmd >/dev/null 2>&1 && { firewall-cmd --add-port=80/tcp --permanent >/dev/null 2>&1 || true; firewall-cmd --reload >/dev/null 2>&1 || true; }
  if [[ ! -f "$HOME/.acme.sh/acme.sh" ]]; then
    curl -fsSL https://get.acme.sh | sh -s email="${ACME_EMAIL:-admin@${ACME_DOMAIN}}" >/dev/null 2>&1 || { echo "acme.sh 安装失败，继续使用自签证书"; return; }
  fi
  local acme="$HOME/.acme.sh/acme.sh"
  "$acme" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  if "$acme" --issue -d "$ACME_DOMAIN" --standalone --keylength ec-256 --httpport 80 >/dev/null 2>&1; then
    "$acme" --install-cert -d "$ACME_DOMAIN" --ecc \
      --fullchain-file "$DATA_DIR/tls/server.crt" \
      --key-file "$DATA_DIR/tls/server.key" \
      --reloadcmd "systemctl restart vpn233-singbox 2>/dev/null || true" >/dev/null 2>&1 || true
    SERVER_NAME="$ACME_DOMAIN"
    echo "ACME 证书已安装到 $DATA_DIR/tls/ (自动续期已配置)"
  else
    echo "ACME 证书申请失败 (检查 80 端口/域名解析)，继续使用自签证书"
  fi
}

install_dependencies() {
  if [[ -n "${PACKAGE_INSTALL:-}" ]]; then
    ${PACKAGE_UPDATE} >/dev/null 2>&1 || true
    ${PACKAGE_INSTALL} -y curl jq tar gzip ca-certificates findutils >/dev/null 2>&1
  fi
}

detect_node_ip() {
  if [[ -n "$NODE_IP" && "$NODE_IP" != "auto" && "$NODE_IP" != "127.0.0.1" ]]; then
    return
  fi
  local candidates=(
    "https://api64.ipify.org"
    "https://ipv4.icanhazip.com"
    "https://ifconfig.me"
  )
  local ip=""
  for url in "${candidates[@]}"; do
    ip="$(curl -fsSL --max-time 5 "$url" 2>/dev/null | tr -d '\r\n' || true)"
    if [[ -n "$ip" ]]; then
      NODE_IP="$ip"
      SERVER_NAME="$ip"
      return
    fi
  done
}

enable_kernel_forwarding() {
  cat >/etc/sysctl.d/99-vpn233-forward.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
  sysctl --system >/dev/null 2>&1 || true
}

install_singbox() {
  if [[ "$USE_SINGBOX" != "true" ]]; then
    return
  fi
  local tag release_json file asset_url
  release_json="$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest)"
  tag="$(echo "$release_json" | jq -r .tag_name | tr -d '\\r\\n')"
  if [[ -z "$tag" || "$tag" == "null" ]]; then
    echo "无法获取 sing-box 版本，使用回退版本 v1.12.0"
    tag="v1.12.0"
  fi
  file="$(echo "$release_json" | jq -r --arg arch "$SINGBOX_ARCH" '.assets[] | select(.name | test("linux-" + $arch + "\\.tar\\.gz$")) | .name' | head -n 1)"
  if [[ -z "$file" || "$file" == "null" ]]; then
    file="sing-box-${tag}-linux-${SINGBOX_ARCH}.tar.gz"
  fi
  asset_url="https://github.com/SagerNet/sing-box/releases/download/${tag}/$file"
  echo "下载 sing-box $tag..."
  curl -fL -o /tmp/$file "$asset_url"
  tar -xzf /tmp/$file -C /tmp
  local bin_path
  bin_path="$(find /tmp -maxdepth 3 -type f -name sing-box | head -n 1)"
  if [[ -z "$bin_path" ]]; then
    echo "未找到 sing-box 可执行文件"
    exit 1
  fi
  install -m 755 "$bin_path" "$DATA_DIR/singbox/sing-box"
  cat >/etc/systemd/system/vpn233-singbox.service <<EOF
[Unit]
Description=vpn233-singbox
After=network.target

[Service]
Type=simple
WorkingDirectory=$DATA_DIR/singbox
ExecStart=$DATA_DIR/singbox/sing-box run -c $DATA_DIR/singbox/config.json
Restart=always
RestartSec=2
LimitNOFILE=$CONN_LIMIT
LimitNPROC=$CONN_LIMIT
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
}

install_mihomo() {
  if [[ "$USE_MIHOMO" != "true" ]]; then
    return
  fi
  local tag release_json asset_name asset_url extracted
  release_json="$(curl -fsSL https://api.github.com/repos/MetaCubeX/mihomo/releases/latest)"
  tag="$(echo "$release_json" | jq -r .tag_name | tr -d '\\r\\n')"
  if [[ -z "$tag" || "$tag" == "null" ]]; then
    tag="v1.18.9"
  fi
  asset_name="$(echo "$release_json" | jq -r --arg arch "$MIHOMO_ARCH" '.assets[] | select(.name | ascii_downcase | test("linux.*" + $arch)) | .name' | head -n 1)"
  if [[ -z "$asset_name" || "$asset_name" == "null" ]]; then
    asset_name="mihomo-linux-${MIHOMO_ARCH}.gz"
  fi
  asset_url="https://github.com/MetaCubeX/mihomo/releases/download/${tag}/${asset_name}"
  curl -fL -o "/tmp/${asset_name}" "$asset_url" || {
    echo "mihomo 下载失败，可能已改名，请手动检查资产"
    return
  }
  extracted="/tmp/${asset_name%.gz}"
  if [[ "$asset_name" == *.gz ]]; then
    gzip -df "/tmp/${asset_name}"
  fi
  if [[ ! -f "$extracted" ]]; then
    extracted="$(find /tmp -maxdepth 2 -type f -name 'mihomo*' | head -n 1)"
  fi
  if [[ -z "$extracted" || ! -f "$extracted" ]]; then
    echo "未找到 mihomo 可执行文件"
    return
  fi
  install -m 755 "$extracted" "$DATA_DIR/mihomo/mihomo"
  cat >/etc/systemd/system/vpn233-mihomo.service <<EOF
[Unit]
Description=vpn233-mihomo
After=network.target

[Service]
Type=simple
WorkingDirectory=$DATA_DIR/mihomo
ExecStart=$DATA_DIR/mihomo/mihomo -d $DATA_DIR/mihomo -f $DATA_DIR/mihomo/config.yaml
Restart=always
RestartSec=2
LimitNOFILE=$CONN_LIMIT
LimitNPROC=$CONN_LIMIT
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
}

write_configs() {
  mkdir -p "$DATA_DIR/singbox" "$DATA_DIR/mihomo" "$DATA_DIR/tls" "$DATA_DIR/runtime"
  cat >"$DATA_DIR/tls/server.crt" <<'EOF'
{{.TLSCertPEM}}
EOF
  cat >"$DATA_DIR/tls/server.key" <<'EOF'
{{.TLSKeyPEM}}
EOF
  if [[ "$USE_SINGBOX" == "true" ]]; then
    cat >"$DATA_DIR/singbox/config.json" <<EOF
{{.SingBoxConfig}}
EOF
  fi
  if [[ "$USE_MIHOMO" == "true" ]]; then
    cat >"$DATA_DIR/mihomo/config.yaml" <<EOF
{{.MihomoConfig}}
EOF
  fi
}

write_runtime_metadata() {
  mkdir -p "$DATA_DIR/runtime"
  jq -n \
    --arg generated_at "$GENERATED_AT" \
    --arg node_name "$NODE_NAME" \
    --arg node_ip "$NODE_IP" \
    --arg server_name "$SERVER_NAME" \
    --arg uuid "$UUID" \
    --arg password "$PASSWORD" \
    --arg grpc_service_name "$GRPC_SERVICE_NAME" \
    --arg reality_public_key "$REALITY_PUBLIC_KEY" \
    --arg reality_short_id "$REALITY_SHORT_ID" \
    --arg reality_server "$REALITY_SERVER" \
    --arg wireguard_client_key "$WG_CLIENT_KEY" \
    --arg wireguard_server_public_key "$WG_SERVER_PUBLIC_KEY" \
    --arg wireguard_preshared_key "$WG_PRESHARED_KEY" \
    --arg wireguard_client_cidr "$WG_CLIENT_CIDR" \
    --argjson ports "$PORTS_JSON" \
    '
    def link($p):
      if $p.id == "singbox-vless" then
        "vless://" + $uuid + "@" + $node_ip + ":" + ($p.port|tostring) + "?security=none&type=tcp#" + $p.name
      elif $p.id == "singbox-vless-grpc" then
        "vless://" + $uuid + "@" + $node_ip + ":" + ($p.port|tostring) + "?security=tls&sni=" + $server_name + "&type=grpc&serviceName=" + $grpc_service_name + "#" + $p.name
      elif $p.id == "singbox-vless-reality" then
        "vless://" + $uuid + "@" + $node_ip + ":" + ($p.port|tostring) + "?security=reality&sni=" + $reality_server + "&pbk=" + $reality_public_key + "&sid=" + $reality_short_id + "&type=tcp#" + $p.name
      elif $p.id == "singbox-vless-reality-grpc" then
        "vless://" + $uuid + "@" + $node_ip + ":" + ($p.port|tostring) + "?security=reality&sni=" + $reality_server + "&pbk=" + $reality_public_key + "&sid=" + $reality_short_id + "&type=grpc&serviceName=" + $grpc_service_name + "#" + $p.name
      elif $p.id == "singbox-anytls" then
        "anytls://" + $password + "@" + $node_ip + ":" + ($p.port|tostring) + "/?sni=" + $server_name + "&insecure=1#" + $p.name
      elif $p.id == "singbox-trojan" then
        "trojan://" + $password + "@" + $node_ip + ":" + ($p.port|tostring) + "?sni=" + $server_name + "#" + $p.name
      elif $p.id == "singbox-trojan-grpc" then
        "trojan://" + $password + "@" + $node_ip + ":" + ($p.port|tostring) + "?sni=" + $server_name + "&type=grpc&serviceName=" + $grpc_service_name + "#" + $p.name
      elif $p.id == "singbox-shadowsocks" then
        "ss://" + ("2022-blake3-chacha20-poly1305:" + $password | @base64) + "@" + $node_ip + ":" + ($p.port|tostring) + "#" + $p.name
      elif $p.id == "singbox-hysteria2" then
        "hysteria2://" + $password + "@" + $node_ip + ":" + ($p.port|tostring) + "?sni=" + $server_name + "&insecure=1#" + $p.name
      elif $p.id == "singbox-tuic" then
        "tuic://" + $uuid + ":" + $password + "@" + $node_ip + ":" + ($p.port|tostring) + "?sni=" + $server_name + "&congestion_control=bbr#" + $p.name
      elif $p.id == "singbox-wireguard" then
        "wireguard://" + $wireguard_client_key + "@" + $node_ip + ":" + ($p.port|tostring) + "?publickey=" + $wireguard_server_public_key + "&presharedkey=" + $wireguard_preshared_key + "&address=" + $wireguard_client_cidr + "#" + $p.name
      elif $p.id == "singbox-socks" then
        "socks5://vpn233:" + $password + "@" + $node_ip + ":" + ($p.port|tostring) + "#" + $p.name
      elif $p.id == "singbox-http" then
        "http://vpn233:" + $password + "@" + $node_ip + ":" + ($p.port|tostring) + "#" + $p.name
      else empty end;
    {
      generated_at: $generated_at,
      node_name: $node_name,
      node_ip: $node_ip,
      server_name: $server_name,
      uuid: $uuid,
      password: $password,
      grpc_service_name: $grpc_service_name,
      reality_server: $reality_server,
      reality_public_key: $reality_public_key,
      reality_short_id: $reality_short_id,
      wireguard_client_private_key: $wireguard_client_key,
      wireguard_server_public_key: $wireguard_server_public_key,
      wireguard_preshared_key: $wireguard_preshared_key,
      wireguard_client_cidr: $wireguard_client_cidr,
      ports: $ports,
      links: [$ports[] | select(.core == "singbox") | link(.)]
    }' >"$DATA_DIR/runtime/node-manifest.json"
  jq -r '.links[]' "$DATA_DIR/runtime/node-manifest.json" >"$DATA_DIR/runtime/links.txt"
}

install_management_cli() {
  cat >/usr/local/bin/vpn233-node <<EOF
#!/usr/bin/env bash
set -euo pipefail
DATA_DIR="$DATA_DIR"
NODE_NAME="$NODE_NAME"
GENERATED_AT="$GENERATED_AT"
SINGBOX_CONFIG="\$DATA_DIR/singbox/config.json"
MANIFEST="\$DATA_DIR/runtime/node-manifest.json"
LINKS="\$DATA_DIR/runtime/links.txt"
restart_services() {
  command -v systemctl >/dev/null 2>&1 && systemctl restart vpn233-singbox vpn233-mihomo >/dev/null 2>&1 || true
}
edit_singbox() {
  local filter="\$1"
  local tmp
  tmp="\$(mktemp)"
  jq "\$filter" "\$SINGBOX_CONFIG" >"\$tmp"
  mv "\$tmp" "\$SINGBOX_CONFIG"
  restart_services
}
case "\${1:-help}" in
  status)
    command -v systemctl >/dev/null 2>&1 && systemctl status vpn233-singbox vpn233-mihomo --no-pager || true
    ;;
  restart)
    restart_services
    ;;
  stop)
    command -v systemctl >/dev/null 2>&1 && systemctl stop vpn233-singbox vpn233-mihomo >/dev/null 2>&1 || true
    ;;
  show-manifest)
    cat "\$MANIFEST"
    ;;
  show-links)
    cat "\$LINKS"
    ;;
  show-config)
    cat "\$SINGBOX_CONFIG"
    ;;
  enable-bt-block)
    edit_singbox '(.route.rules //= []) as \$rules | if any(\$rules[]?; (.protocol? == "bittorrent") or (.protocol? == ["bittorrent"])) then . else .route.rules += [{"protocol":"bittorrent","outbound":"block"}] end'
    ;;
  disable-bt-block)
    edit_singbox '.route.rules |= map(select((.protocol? != "bittorrent") and (.protocol? != ["bittorrent"])))'
    ;;
  add-block-domain)
    test -n "\${2:-}" || { echo "usage: vpn233-node add-block-domain example.com"; exit 1; }
    edit_singbox "\$(printf '.route.rules += [{\"domain_suffix\":[\"%s\"],\"outbound\":\"block\"}]' "\$2")"
    ;;
  remove-block-domain)
    test -n "\${2:-}" || { echo "usage: vpn233-node remove-block-domain example.com"; exit 1; }
    edit_singbox "\$(printf '.route.rules |= map(if .domain_suffix? then .domain_suffix |= map(select(. != \"%s\")) else . end) | .route.rules |= map(select((.domain_suffix? | length // 1) > 0 or (.outbound? != \"block\")))' "\$2")"
    ;;
  stats)
    echo "== services =="
    command -v systemctl >/dev/null 2>&1 && systemctl is-active vpn233-singbox vpn233-mihomo 2>/dev/null || true
    echo "== sockets =="
    command -v ss >/dev/null 2>&1 && ss -s || true
    echo "== conntrack =="
    [ -r /proc/sys/net/netfilter/nf_conntrack_count ] && cat /proc/sys/net/netfilter/nf_conntrack_count || true
    ;;
  top)
    command -v ss >/dev/null 2>&1 && ss -tunp 2>/dev/null | head -n 50 || netstat -tunp 2>/dev/null | head -n 50 || true
    ;;
  doctor)
    echo "node: \$NODE_NAME (\$GENERATED_AT)"
    echo "data: \$DATA_DIR"
    for svc in vpn233-singbox vpn233-mihomo; do
      if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q "\${svc}.service"; then
        printf '%s: ' "\$svc"; systemctl is-active "\$svc" 2>/dev/null || true
      fi
    done
    echo "congestion: \$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
    echo "nofile: \$(ulimit -n)"
    if [ -f "\$DATA_DIR/tls/server.crt" ] && command -v openssl >/dev/null 2>&1; then
      echo "cert: \$(openssl x509 -enddate -noout -in "\$DATA_DIR/tls/server.crt" 2>/dev/null || echo n/a)"
    fi
    ;;
  speedtest)
    if command -v speedtest-cli >/dev/null 2>&1; then
      speedtest-cli --simple || true
    else
      echo "下载测速中 (100MB)..."
      curl -o /dev/null -w "下行速度: %{speed_download} B/s\n" -s "https://speed.cloudflare.com/__down?bytes=104857600" || true
    fi
    ;;
  version)
    echo "vpn233-node: \$NODE_NAME (\$GENERATED_AT)"
    [ -x "\$DATA_DIR/singbox/sing-box" ] && "\$DATA_DIR/singbox/sing-box" version 2>/dev/null | head -n1 || true
    [ -x "\$DATA_DIR/mihomo/mihomo" ] && "\$DATA_DIR/mihomo/mihomo" -v 2>/dev/null | head -n1 || true
    ;;
  backup)
    out="\${2:-/root/vpn233-backup-\$(date +%Y%m%d%H%M%S).tar.gz}"
    tar -czf "\$out" -C "\$(dirname "\$DATA_DIR")" "\$(basename "\$DATA_DIR")" && echo "已备份到 \$out"
    ;;
  restore)
    test -n "\${2:-}" || { echo "usage: vpn233-node restore <backup.tar.gz>"; exit 1; }
    tar -xzf "\$2" -C "\$(dirname "\$DATA_DIR")" && echo "已从 \$2 恢复" && restart_services
    ;;
  cert-renew)
    if [ -x "\$HOME/.acme.sh/acme.sh" ]; then
      "\$HOME/.acme.sh/acme.sh" --renew-all --ecc || true
      restart_services
    else
      echo "未安装 acme.sh"
    fi
    ;;
  update)
    arch="\$(uname -m)"
    case "\$arch" in x86_64|amd64) a=amd64;; aarch64|arm64) a=arm64;; *) echo "不支持的架构: \$arch"; exit 1;; esac
    if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q vpn233-singbox.service; then
      t="\$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name)"
      f="sing-box-\${t#v}-linux-\${a}.tar.gz"
      if curl -fL -o "/tmp/\$f" "https://github.com/SagerNet/sing-box/releases/download/\${t}/\$f"; then
        tar -xzf "/tmp/\$f" -C /tmp
        b="\$(find /tmp -maxdepth 3 -type f -name sing-box | head -n1)"
        [ -n "\$b" ] && install -m 755 "\$b" "\$DATA_DIR/singbox/sing-box" && echo "sing-box 已更新到 \$t"
      fi
    fi
    if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -q vpn233-mihomo.service; then
      mt="\$(curl -fsSL https://api.github.com/repos/MetaCubeX/mihomo/releases/latest | jq -r .tag_name)"
      ma="mihomo-linux-\${a}-\${mt}.gz"
      if curl -fL -o "/tmp/\$ma" "https://github.com/MetaCubeX/mihomo/releases/download/\${mt}/\${ma}"; then
        gzip -df "/tmp/\$ma" 2>/dev/null || true
        mb="\$(find /tmp -maxdepth 2 -type f -name 'mihomo-linux-*' | head -n1)"
        [ -n "\$mb" ] && install -m 755 "\$mb" "\$DATA_DIR/mihomo/mihomo" && echo "mihomo 已更新到 \$mt"
      fi
    fi
    restart_services
    ;;
  uninstall)
    read -r -p "确认卸载 vpn233 节点? (yes/no) " ans
    [ "\$ans" = "yes" ] || { echo "已取消"; exit 0; }
    if command -v systemctl >/dev/null 2>&1; then
      systemctl disable --now vpn233-singbox vpn233-mihomo vpn233-watchdog.timer >/dev/null 2>&1 || true
      rm -f /etc/systemd/system/vpn233-singbox.service /etc/systemd/system/vpn233-mihomo.service /etc/systemd/system/vpn233-watchdog.service /etc/systemd/system/vpn233-watchdog.timer
      systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    rm -f /usr/local/bin/vpn233-watchdog /etc/logrotate.d/vpn233 /etc/sysctl.d/99-vpn233.conf /etc/sysctl.d/99-vpn233-security.conf
    rm -rf "\$DATA_DIR"
    echo "已卸载 vpn233 节点"
    rm -f /usr/local/bin/vpn233-node
    ;;
  reload)
    restart_services
    ;;
  *)
    cat <<USAGE
vpn233-node status
vpn233-node restart
vpn233-node stop
vpn233-node reload
vpn233-node show-manifest
vpn233-node show-links
vpn233-node show-config
vpn233-node stats
vpn233-node top
vpn233-node doctor
vpn233-node speedtest
vpn233-node version
vpn233-node backup [path]
vpn233-node restore <backup.tar.gz>
vpn233-node update
vpn233-node cert-renew
vpn233-node uninstall
vpn233-node enable-bt-block
vpn233-node disable-bt-block
vpn233-node add-block-domain example.com
vpn233-node remove-block-domain example.com
USAGE
    ;;
esac
EOF
  chmod 755 /usr/local/bin/vpn233-node
}

open_ports() {
  for p in ${PORT_LIST//,/ }; do
    if command -v ufw >/dev/null 2>&1; then
      ufw allow "$p"/tcp >/dev/null 2>&1 || true
      ufw allow "$p"/udp >/dev/null 2>&1 || true
    elif command -v firewall-cmd >/dev/null 2>&1; then
      firewall-cmd --zone=public --add-port="$p/tcp" --permanent >/dev/null 2>&1 || true
      firewall-cmd --zone=public --add-port="$p/udp" --permanent >/dev/null 2>&1 || true
      firewall-cmd --reload >/dev/null 2>&1 || true
    else
      iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$p" -j ACCEPT
      iptables -C INPUT -p udp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport "$p" -j ACCEPT
    fi
  done
}

enable_services() {
  if [[ "$USE_SINGBOX" == "true" ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable --now vpn233-singbox >/dev/null 2>&1 || true
  fi
  if [[ "$USE_MIHOMO" == "true" ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable --now vpn233-mihomo >/dev/null 2>&1 || true
  fi
}

verify_services() {
  if [[ "$USE_SINGBOX" == "true" ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl is-active --quiet vpn233-singbox || {
      echo "vpn233-singbox 未能成功启动"
      journalctl -u vpn233-singbox -n 50 --no-pager || true
      exit 1
    }
  fi
  if [[ "$USE_MIHOMO" == "true" ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl is-active --quiet vpn233-mihomo || {
      echo "vpn233-mihomo 未能成功启动"
      journalctl -u vpn233-mihomo -n 50 --no-pager || true
      exit 1
    }
  fi
}

install_dependencies
detect_node_ip
tune_performance
apply_resource_limits
apply_security_hardening
enable_kernel_forwarding
write_configs
issue_acme_cert
write_runtime_metadata
install_management_cli
install_logrotate
install_fail2ban
install_watchdog
open_ports
if [[ "$USE_SINGBOX" == "true" || "$USE_MIHOMO" == "true" ]]; then
  install_singbox
  install_mihomo
fi
enable_services
verify_services

cat <<EOF
========================================
节点信息（仅显示关键配置）
节点名: $NODE_NAME
服务名: $SERVER_NAME
UUID: $UUID
节点口令: $PASSWORD
gRPC 服务名: $GRPC_SERVICE_NAME
Reality 公钥: $REALITY_PUBLIC_KEY
Reality ShortID: $REALITY_SHORT_ID
WireGuard 客户端私钥: $WG_CLIENT_KEY
WireGuard 服务端公钥: $WG_SERVER_PUBLIC_KEY
WireGuard PresharedKey: $WG_PRESHARED_KEY
WireGuard 客户端地址: $WG_CLIENT_CIDR
运行时清单: $DATA_DIR/runtime/node-manifest.json
连接链接: $DATA_DIR/runtime/links.txt
管理命令: vpn233-node (status/stats/doctor/speedtest/backup/update/uninstall...)
数据目录: $DATA_DIR
拥塞控制: $TCP_CONGESTION  TFO: $ENABLE_TCP_FASTOPEN  连接上限: $CONN_LIMIT
安全加固: $ENABLE_HARDENING  fail2ban: $ENABLE_FAIL2BAN  看门狗: $ENABLE_WATCHDOG
ACME 证书: $ENABLE_ACME  域名: $ACME_DOMAIN
生成时间: $GENERATED_AT
支持端口: $PORT_LIST
========================================
EOF
`

const ps1InstallTemplate = `#requires -version 5.1
$ErrorActionPreference = "Stop"
$NODE_NAME = "{{.NodeName}}"
$NODE_IP = "{{.NodeIP}}"
$SERVER_NAME = "{{.ServerName}}"
$DATA_DIR = "{{.DataDir}}"
$USE_MIHOMO = {{if .UseMihomo}}$true{{else}}$false{{end}}
$USE_SINGBOX = {{if .UseSingbox}}$true{{else}}$false{{end}}
$ENABLE_BBR = {{if .EnableBBR}}$true{{else}}$false{{end}}
$ENABLE_TCP_FASTOPEN = {{if .EnableTCPFastOpen}}$true{{else}}$false{{end}}
$ENABLE_HARDENING = {{if .EnableHardening}}$true{{else}}$false{{end}}
$CONN_LIMIT = {{.ConnLimit}}
$PASSWORD = "{{.Password}}"
$GRPC_SERVICE_NAME = "{{.GRPCServiceName}}"
$REALITY_PUBLIC_KEY = "{{.RealityPublicKey}}"
$REALITY_SHORT_ID = "{{.RealityShortID}}"
$WG_CLIENT_KEY = "{{.WireGuardClientPrivateKey}}"
$WG_SERVER_PUBLIC_KEY = "{{.WireGuardServerPublicKey}}"
$WG_PRESHARED_KEY = "{{.WireGuardPresharedKey}}"
$WG_CLIENT_CIDR = "{{.WireGuardClientCIDR}}"
$PORT_LIST = "{{.PortsCSV}}".Split(",")
$GeneratedAt = "{{.GeneratedAt}}"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "请使用管理员运行 PowerShell"
}

New-Item -ItemType Directory -Path "$DATA_DIR\singbox","$DATA_DIR\mihomo","$DATA_DIR\tls" -Force | Out-Null

function Optimize-Performance {
  if (-not $ENABLE_BBR) { return }
  try {
    Set-NetTCPSetting -SettingName Internet -AutoTuningLevelNormal -ErrorAction SilentlyContinue
    netsh int tcp set global autotuninglevel=normal 2>$null | Out-Null
    netsh int tcp set global rss=enabled 2>$null | Out-Null
    netsh int tcp set global ecncapability=enabled 2>$null | Out-Null
    netsh int tcp set supplemental Internet congestionprovider=ctcp 2>$null | Out-Null
    if ($ENABLE_TCP_FASTOPEN) {
      netsh int tcp set global fastopen=enabled 2>$null | Out-Null
      netsh int tcp set global fastopenfallback=enabled 2>$null | Out-Null
    }
    $tcpip = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    Set-ItemProperty -Path $tcpip -Name "MaxUserPort" -Value 65534 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $tcpip -Name "TcpTimedWaitDelay" -Value 30 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Output "已应用 Windows 网络性能优化 (autotuning/RSS/CTCP/TFO)"
  } catch {
    Write-Output "网络性能优化部分失败: $($_.Exception.Message)"
  }
}

function Protect-Host {
  if (-not $ENABLE_HARDENING) { return }
  try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue
    Write-Output "已启用 Windows 防火墙加固"
  } catch {
    Write-Output "防火墙加固失败: $($_.Exception.Message)"
  }
}

Optimize-Performance
Protect-Host

function Write-Config {
  $sing = @'
{{.SingBoxConfig}}
'@
  $mih = @'
{{.MihomoConfig}}
'@
  $crt = @'
{{.TLSCertPEM}}
'@
  $key = @'
{{.TLSKeyPEM}}
'@
  $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText("$DATA_DIR\tls\server.crt", $crt, [System.Text.Encoding]::ASCII)
  [System.IO.File]::WriteAllText("$DATA_DIR\tls\server.key", $key, [System.Text.Encoding]::ASCII)
  if ($USE_SINGBOX) {
    [System.IO.File]::WriteAllText("$DATA_DIR\singbox\config.json", $sing, $utf8NoBom)
  }
  if ($USE_MIHOMO) {
    [System.IO.File]::WriteAllText("$DATA_DIR\mihomo\config.yaml", $mih, $utf8NoBom)
  }
}

function Install-SingBox {
  if (-not $USE_SINGBOX) { return }
  $arch = (Get-CimInstance Win32_Processor).Architecture
  if ($arch -eq 9) { $archTag = "amd64" } else { $archTag = "amd64" }
  $tagObj = Invoke-RestMethod -Uri "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
  $tag = $tagObj.tag_name
  $asset = "sing-box-$tag-win64.zip"
  $tmp = Join-Path $env:TEMP $asset
  Invoke-WebRequest -Uri "https://github.com/SagerNet/sing-box/releases/download/$tag/$asset" -OutFile $tmp
  Expand-Archive -Path $tmp -DestinationPath (Join-Path $DATA_DIR "singbox") -Force
  $exe = Get-ChildItem "$DATA_DIR\\singbox" -Recurse -Filter sing-box*.exe | Select-Object -First 1
  if ($exe) {
    $serviceCommand = '"' + $exe.FullName + '" run -c "' + $DATA_DIR + "\\singbox\\config.json"'
    New-Service -Name "vpn233-singbox" -BinaryPathName $serviceCommand -DisplayName "vpn233-singbox" -StartupType Automatic -ErrorAction SilentlyContinue | Out-Null
  }
}

function Install-Mihomo {
  if (-not $USE_MIHOMO) { return }
  $tagObj = Invoke-RestMethod -Uri "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
  $tag = $tagObj.tag_name
  $asset = "mihomo-windows-amd64.exe"
  $tmp = Join-Path $env:TEMP $asset
  Invoke-WebRequest -Uri "https://github.com/MetaCubeX/mihomo/releases/download/$tag/$asset" -OutFile $tmp -ErrorAction SilentlyContinue
  Copy-Item $tmp "$DATA_DIR\\mihomo\\mihomo.exe" -Force
  $mihomoServiceCommand = '"' + $DATA_DIR + '\\mihomo\\mihomo.exe" -d "' + $DATA_DIR + '\\mihomo" -f "' + $DATA_DIR + '\\mihomo\\config.yaml"'
  New-Service -Name "vpn233-mihomo" -BinaryPathName $mihomoServiceCommand -DisplayName "vpn233-mihomo" -StartupType Automatic -ErrorAction SilentlyContinue | Out-Null
}

function Open-Ports {
  foreach ($p in $PORT_LIST) {
    if (-not [string]::IsNullOrWhiteSpace($p)) {
      New-NetFirewallRule -DisplayName "VPN233-$p" -Direction Inbound -Protocol TCP -Action Allow -LocalPort $p -Profile Any -ErrorAction SilentlyContinue | Out-Null
      New-NetFirewallRule -DisplayName "VPN233-UDP-$p" -Direction Inbound -Protocol UDP -Action Allow -LocalPort $p -Profile Any -ErrorAction SilentlyContinue | Out-Null
    }
  }
}

Write-Config
Install-SingBox
Install-Mihomo
Open-Ports
Start-Service vpn233-singbox -ErrorAction SilentlyContinue
Start-Service vpn233-mihomo -ErrorAction SilentlyContinue

Write-Output "========================================"
Write-Output "节点名: $NODE_NAME"
Write-Output "服务名: $SERVER_NAME"
Write-Output "口令: $PASSWORD"
Write-Output "gRPC 服务名: $GRPC_SERVICE_NAME"
Write-Output "Reality 公钥: $REALITY_PUBLIC_KEY"
Write-Output "Reality ShortID: $REALITY_SHORT_ID"
Write-Output "WireGuard 客户端私钥: $WG_CLIENT_KEY"
Write-Output "WireGuard 服务端公钥: $WG_SERVER_PUBLIC_KEY"
Write-Output "WireGuard PresharedKey: $WG_PRESHARED_KEY"
Write-Output "WireGuard 客户端地址: $WG_CLIENT_CIDR"
Write-Output "数据目录: $DATA_DIR"
Write-Output "性能优化: $ENABLE_BBR  TFO: $ENABLE_TCP_FASTOPEN  防火墙加固: $ENABLE_HARDENING"
Write-Output "连接上限(参考): $CONN_LIMIT"
Write-Output "端口列表: $($PORT_LIST -join ',')"
Write-Output "生成时间: $GeneratedAt"
Write-Output "管理: Start-Service/Stop-Service vpn233-singbox | vpn233-mihomo"
Write-Output "========================================"
`
