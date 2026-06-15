package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSubscribeVerifyHandlerTokenMismatch(t *testing.T) {
	restoreWD := withWorkingDir(t, t.TempDir())
	defer restoreWD()

	restoreGit := withGitRunner(t, func(_ string, args ...string) (string, error) {
		switch {
		case args[0] == "rev-parse" && args[1] == "--is-inside-work-tree":
			return "true", nil
		case args[0] == "rev-parse" && args[1] == "--show-toplevel":
			return ".", nil
		case args[0] == "rev-parse" && args[1] == "--show-superproject-working-tree":
			return "", nil
		case args[0] == "rev-parse" && args[1] == "--git-dir":
			return ".git", nil
		default:
			return "", nil
		}
	})
	defer restoreGit()

	state := &AppState{
		cfg:        normalizeRepoDefaults(ServerConfig{SubscribeVerifyToken: "secret"}),
		tokenUntil: make(map[string]time.Time),
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/subscribe/verify?token=wrong", nil)
	rec := httptest.NewRecorder()
	state.subscribeVerifyHandler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expect 401, got %d", rec.Code)
	}
}

func TestSubscribeVerifyHandlerOk(t *testing.T) {
	restoreWD := withWorkingDir(t, t.TempDir())
	defer restoreWD()

	restoreGit := withGitRunner(t, func(_ string, args ...string) (string, error) {
		switch {
		case args[0] == "rev-parse" && args[1] == "--is-inside-work-tree":
			return "true", nil
		case args[0] == "rev-parse" && args[1] == "--show-toplevel":
			return ".", nil
		case args[0] == "rev-parse" && args[1] == "--show-superproject-working-tree":
			return "", nil
		case args[0] == "rev-parse" && args[1] == "--git-dir":
			return ".git", nil
		default:
			return "", nil
		}
	})
	defer restoreGit()

	state := &AppState{
		cfg:        normalizeRepoDefaults(ServerConfig{SubscribeVerifyToken: "secret"}),
		tokenUntil: make(map[string]time.Time),
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/subscribe/verify?token=secret", nil)
	rec := httptest.NewRecorder()
	state.subscribeVerifyHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expect 200, got %d", rec.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if body["ok"] != true {
		t.Fatalf("expect ok=true, got %v", body["ok"])
	}
	if body["service"] != "vpn233-provider-server" {
		t.Fatalf("unexpected service value: %v", body["service"])
	}
}

func TestGenerateArtifactsWithSelectedProtocols(t *testing.T) {
	state := &AppState{
		cfg:        defaultConfig(),
		tokenUntil: make(map[string]time.Time),
	}
	state.cfg.DefaultDataDir = "/etc/vpn233"

	req := InstallRequest{
		NodeName:          "test-node",
		NodeIP:            "127.0.0.1",
		UseMihomo:         boolPtr(false),
		UseSingbox:        boolPtr(true),
		EnableBBR:         boolPtr(true),
		PortBase:          12000,
		SelectedProtocols:  []string{"singbox-vless", "singbox-vmess", "singbox-trojan"},
		AdminPassword:      "pass",
	}
	res, err := state.generateArtifacts(req)
	if err != nil {
		t.Fatalf("generate artifacts failed: %v", err)
	}
	if res.Node.Name != "test-node" {
		t.Fatalf("unexpected node name: %s", res.Node.Name)
	}
	if len(res.Node.Ports) != 3 {
		t.Fatalf("expect 3 ports, got %d", len(res.Node.Ports))
	}
	if !strings.Contains(res.Shell, "DATA_DIR=") {
		t.Fatalf("shell script should contain DATA_DIR")
	}
	if !strings.Contains(res.PS1, "DATA_DIR") {
		t.Fatalf("ps1 script should contain DATA_DIR")
	}
}

func TestGenerateArtifactsExpandedProtocolTemplates(t *testing.T) {
	state := &AppState{
		cfg:        defaultConfig(),
		tokenUntil: make(map[string]time.Time),
	}
	state.cfg.DefaultDataDir = "/etc/vpn233"

	req := InstallRequest{
		NodeName:   "rich-node",
		NodeIP:     "198.51.100.20",
		UseMihomo:  boolPtr(true),
		UseSingbox: boolPtr(true),
		EnableBBR:  boolPtr(true),
		PortBase:   13000,
		SelectedProtocols: []string{
			"singbox-vless-reality-grpc",
			"singbox-trojan-grpc",
			"mihomo-vless-reality-grpc",
			"mihomo-wireguard",
		},
		AdminPassword: "pass",
	}
	res, err := state.generateArtifacts(req)
	if err != nil {
		t.Fatalf("generate artifacts failed: %v", err)
	}
	if res.Node.RealityPublicKey == "" || res.Node.RealityShortID == "" {
		t.Fatalf("expect reality material to be generated, got %+v", res.Node)
	}
	if res.Node.GRPCServiceName != "vpn233-grpc" {
		t.Fatalf("unexpected grpc service name: %s", res.Node.GRPCServiceName)
	}
	if !strings.Contains(res.Shell, "\"service_name\": \"vpn233-grpc\"") {
		t.Fatalf("shell script should contain grpc transport config")
	}
	if !strings.Contains(res.Shell, "Reality 公钥") {
		t.Fatalf("shell script should surface reality credentials")
	}
	if !strings.Contains(res.PS1, "server.crt") {
		t.Fatalf("ps1 script should write tls files")
	}
	if !strings.Contains(res.PS1, "reality-opts") {
		t.Fatalf("ps1 script should contain mihomo reality template")
	}
	if !strings.Contains(res.Shell, "vpn233-node") {
		t.Fatalf("shell script should install helper command")
	}
	if !strings.Contains(res.Shell, "node-manifest.json") {
		t.Fatalf("shell script should write runtime manifest")
	}
}

func TestGenerateAliasHandlerReturnsRawShell(t *testing.T) {
	state := &AppState{
		cfg:        defaultConfig(),
		tokenUntil: make(map[string]time.Time),
	}
	req := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/generate.sh?node_name=raw-node&node_ip=203.0.113.7&use_singbox=true&use_mihomo=false&selected_protocols=singbox-vless-grpc,singbox-vless-reality-grpc",
		nil,
	)
	rec := httptest.NewRecorder()
	state.generateAliasHandler("sh")(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expect 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Disposition"); !strings.Contains(got, "raw-node-install.sh") {
		t.Fatalf("unexpected content disposition: %s", got)
	}
	if !strings.Contains(rec.Body.String(), "#!/usr/bin/env bash") {
		t.Fatalf("expected shell output")
	}
	if !strings.Contains(rec.Body.String(), "Reality 公钥") {
		t.Fatalf("expected raw shell to include reality metadata")
	}
}

func TestMihomoSelectionAutoAddsMatchingSingBoxPort(t *testing.T) {
	state := &AppState{
		cfg:        defaultConfig(),
		tokenUntil: make(map[string]time.Time),
	}
	req := InstallRequest{
		NodeName:          "pair-node",
		NodeIP:            "203.0.113.10",
		SelectedProtocols: []string{"mihomo-vless-grpc"},
	}
	res, err := state.generateArtifacts(req)
	if err != nil {
		t.Fatalf("generate artifacts failed: %v", err)
	}
	if len(res.Node.Ports) != 2 {
		t.Fatalf("expected mihomo entry plus matching singbox entry, got %d", len(res.Node.Ports))
	}
	if res.Node.Ports[0].Port != res.Node.Ports[1].Port {
		t.Fatalf("expected paired protocols to share one port, got %+v", res.Node.Ports)
	}
}

func TestLocalGenerateAliasAllowsLoopbackWithoutAuth(t *testing.T) {
	state := &AppState{
		cfg:        defaultConfig(),
		tokenUntil: make(map[string]time.Time),
	}
	req := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/local/generate.sh?node_name=local-node&node_ip=203.0.113.8&use_singbox=true&use_mihomo=false&selected_protocols=singbox-vless-grpc",
		nil,
	)
	req.RemoteAddr = "127.0.0.1:34567"
	rec := httptest.NewRecorder()
	buildMux(state).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expect 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "#!/usr/bin/env bash") {
		t.Fatalf("expected shell output from local alias route")
	}
}

func TestLocalProtocolsRejectsNonLoopback(t *testing.T) {
	state := &AppState{
		cfg:        defaultConfig(),
		tokenUntil: make(map[string]time.Time),
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/local/protocols", nil)
	req.RemoteAddr = "203.0.113.9:45678"
	rec := httptest.NewRecorder()
	buildMux(state).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expect 403, got %d", rec.Code)
	}
}

func TestRunCLIConfigSetUpdatesConfig(t *testing.T) {
	state := &AppState{
		cfgPath:    t.TempDir() + "/agent-config.json",
		cfg:        defaultConfig(),
		tokenUntil: make(map[string]time.Time),
	}
	var out strings.Builder
	err := runCLI(state, &out, []string{
		"config",
		"set",
		"--listen-port", "18080",
		"--default-use-mihomo=true",
		"--default-use-singbox=false",
		"--default-node-ip", "198.51.100.88",
	})
	if err != nil {
		t.Fatalf("runCLI config set failed: %v", err)
	}
	cfg := state.snapshotConfig()
	if cfg.ListenPort != 18080 {
		t.Fatalf("expected listen port 18080, got %d", cfg.ListenPort)
	}
	if !cfg.DefaultUseMihomo {
		t.Fatalf("expected default Mihomo enabled")
	}
	if cfg.DefaultUseSingbox {
		t.Fatalf("expected default sing-box disabled")
	}
	if cfg.DefaultNodeIP != "198.51.100.88" {
		t.Fatalf("unexpected default node ip: %s", cfg.DefaultNodeIP)
	}
}

func TestRunCLIGenerateShell(t *testing.T) {
	state := &AppState{
		cfg:        defaultConfig(),
		tokenUntil: make(map[string]time.Time),
	}
	var out strings.Builder
	err := runCLI(state, &out, []string{
		"generate",
		"--format=sh",
		"--node-name=edge-01",
		"--node-ip=203.0.113.10",
		"--use-singbox=true",
		"--use-mihomo=false",
		"--protocols=singbox-vless,singbox-trojan",
	})
	if err != nil {
		t.Fatalf("runCLI generate failed: %v", err)
	}
	if !strings.Contains(out.String(), "#!/usr/bin/env bash") {
		t.Fatalf("expected shell output")
	}
	if !strings.Contains(out.String(), "edge-01") {
		t.Fatalf("expected generated shell to contain node name")
	}
}

func boolPtr(v bool) *bool {
	return &v
}
