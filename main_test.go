package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		SelectedProtocols: []string{"singbox-vless", "singbox-vmess", "singbox-trojan"},
		AdminPassword:     "pass",
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

func TestGenerateHandlerGetDefaultsToRawShell(t *testing.T) {
	state := &AppState{
		cfg:        defaultConfig(),
		tokenUntil: make(map[string]time.Time),
	}
	req := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/generate?node_name=direct-node&node_ip=203.0.113.40&use_singbox=true&use_mihomo=false&selected_protocols=singbox-vless",
		nil,
	)
	rec := httptest.NewRecorder()
	state.generateHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expect 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Disposition"); !strings.Contains(got, "direct-node-install.sh") {
		t.Fatalf("unexpected content disposition: %s", got)
	}
	if !strings.Contains(rec.Body.String(), "#!/usr/bin/env bash") {
		t.Fatalf("expected raw shell output")
	}
}

func TestGenerateHandlerGetJSONFormatSupported(t *testing.T) {
	state := &AppState{
		cfg:        defaultConfig(),
		tokenUntil: make(map[string]time.Time),
	}
	req := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/generate?node_name=direct-json&node_ip=203.0.113.41&format=json&use_singbox=true&use_mihomo=false&selected_protocols=singbox-vless",
		nil,
	)
	rec := httptest.NewRecorder()
	state.generateHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expect 200, got %d", rec.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if _, ok := body["shell"]; !ok {
		t.Fatalf("json output should contain shell")
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

func TestParseInstallRequestFromQueryProtocolOptions(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/generate?node_ip=203.0.113.200&protocol_options=%7B%22singbox-vless%22%3A%7B%22tag%22%3A%22vip-tag%22%2C%22tag_meta%22%3A%7B%22tier%22%3A%22gold%22%7D%7D%2C%22mihomo-vless%22%3A%7B%22udp%22%3Atrue%2C%22network%22%3A%22tcp%22%7D%7D", nil)
	parsed, err := parseInstallRequestFromQuery(req)
	if err != nil {
		t.Fatalf("parse query failed: %v", err)
	}
	singboxOptions, ok := parsed.ProtocolOptions["singbox-vless"]
	if !ok {
		t.Fatalf("missing singbox-vless options")
	}
	if singboxOptions["tag"] != "vip-tag" {
		t.Fatalf("unexpected singbox-vless tag: %v", singboxOptions["tag"])
	}
	meta, ok := singboxOptions["tag_meta"].(map[string]any)
	if !ok {
		t.Fatalf("missing tag_meta map: %T", singboxOptions["tag_meta"])
	}
	if meta["tier"] != "gold" {
		t.Fatalf("unexpected tag_meta tier: %v", meta["tier"])
	}
	mihomoOptions, ok := parsed.ProtocolOptions["mihomo-vless"]
	if !ok {
		t.Fatalf("missing mihomo-vless options")
	}
	if mihomoOptions["udp"] != true {
		t.Fatalf("unexpected mihomo-vless udp: %v", mihomoOptions["udp"])
	}
	if mihomoOptions["network"] != "tcp" {
		t.Fatalf("unexpected mihomo-vless network: %v", mihomoOptions["network"])
	}
}

func TestParseInstallRequestFromQueryProtocolOptionsB64(t *testing.T) {
	raw := `{"singbox-vless":{"listen":"127.0.0.1","extra":{"label":"b64"}},"mihomo-vless":{"server":"proxy.example.com"}}`
	enc := base64.StdEncoding.EncodeToString([]byte(raw))
	values := url.Values{}
	values.Set("node_ip", "203.0.113.201")
	values.Set("protocol_options_b64", enc)
	u := &url.URL{
		Path:     "/api/v1/generate",
		RawQuery: values.Encode(),
	}
	req := httptest.NewRequest(http.MethodGet, u.String(), nil)
	parsed, err := parseInstallRequestFromQuery(req)
	if err != nil {
		t.Fatalf("parse query failed: %v", err)
	}
	singboxOptions, ok := parsed.ProtocolOptions["singbox-vless"]
	if !ok {
		t.Fatalf("missing singbox-vless options")
	}
	if singboxOptions["listen"] != "127.0.0.1" {
		t.Fatalf("unexpected singbox listen: %v", singboxOptions["listen"])
	}
	extra, ok := singboxOptions["extra"].(map[string]any)
	if !ok {
		t.Fatalf("unexpected extra type: %T", singboxOptions["extra"])
	}
	if extra["label"] != "b64" {
		t.Fatalf("unexpected label: %v", extra["label"])
	}
}

func TestRunCLIGenerateWithProtocolOptions(t *testing.T) {
	state := &AppState{
		cfg:        defaultConfig(),
		tokenUntil: make(map[string]time.Time),
	}
	var out strings.Builder
	err := runCLI(state, &out, []string{
		"generate",
		"--format=json",
		"--node-name=edge-opt",
		"--node-ip=203.0.113.10",
		"--use-singbox=true",
		"--use-mihomo=false",
		"--protocol-options", `{"singbox-vless":{"tag":"cli-tag","extra":{"x":"y"}}}`,
		"--protocols=singbox-vless",
	})
	if err != nil {
		t.Fatalf("runCLI generate failed: %v", err)
	}
	if !strings.Contains(out.String(), "\"shell\":") {
		t.Fatalf("expected json output")
	}
	if !strings.Contains(out.String(), "\"cli-tag\"") {
		t.Fatalf("protocol option did not apply to singbox template: %s", out.String())
	}
	if !strings.Contains(out.String(), "\"extra\"") {
		t.Fatalf("nested protocol option missing")
	}
}

func TestMihomoOptionOverridesAppliedInConfig(t *testing.T) {
	state := &AppState{
		cfg:        defaultConfig(),
		tokenUntil: make(map[string]time.Time),
	}
	res, err := state.generateArtifacts(InstallRequest{
		NodeName:          "over-node",
		NodeIP:            "203.0.113.50",
		UseSingbox:        boolPtr(true),
		UseMihomo:         boolPtr(true),
		PortBase:          15000,
		SelectedProtocols: []string{"singbox-vless", "mihomo-vless"},
		ProtocolOptions: map[string]map[string]any{
			"mihomo-vless": {
				"network": "tcp",
				"ws-opts": map[string]any{
					"path": "/edge",
					"headers": map[string]any{
						"Host": "example.com",
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("generate artifacts failed: %v", err)
	}
	if !strings.Contains(res.Shell, "network: tcp") {
		t.Fatalf("expected protocol_options override in mihomo config")
	}
	if !strings.Contains(res.Shell, "path: /edge") {
		t.Fatalf("expected ws-opts.path override in mihomo config")
	}
}

func TestProtocolListDomainDefaultsPreferAnyTLS(t *testing.T) {
	state := &AppState{
		cfg:        defaultConfig(),
		tokenUntil: make(map[string]time.Time),
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/protocols?node_ip=panel.example.com", nil)
	rec := httptest.NewRecorder()
	state.protocolListHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expect 200, got %d", rec.Code)
	}
	var items []ProtocolCatalog
	if err := json.NewDecoder(rec.Body).Decode(&items); err != nil {
		t.Fatalf("decode protocol list failed: %v", err)
	}
	foundAnyTLS := false
	foundReality := false
	for _, item := range items {
		if item.ID == "singbox-anytls" && item.Default {
			foundAnyTLS = true
		}
		if item.ID == "singbox-vless-reality" && item.Default {
			foundReality = true
		}
	}
	if !foundAnyTLS {
		t.Fatalf("expected domain mode to default to AnyTLS")
	}
	if foundReality {
		t.Fatalf("did not expect domain mode to default to Reality")
	}
}

func TestGenerateArtifactsDomainAutoDefaultsToAnyTLS(t *testing.T) {
	state := &AppState{
		cfg:        defaultConfig(),
		tokenUntil: make(map[string]time.Time),
	}
	req := InstallRequest{
		NodeName:   "domain-node",
		NodeIP:     "panel.example.com",
		UseSingbox: boolPtr(true),
		UseMihomo:  boolPtr(true),
	}
	res, err := state.generateArtifacts(req)
	if err != nil {
		t.Fatalf("generate artifacts failed: %v", err)
	}
	foundSingboxAnyTLS := false
	foundMihomoAnyTLS := false
	for _, p := range res.Node.Ports {
		if p.ID == "singbox-anytls" {
			foundSingboxAnyTLS = true
		}
		if p.ID == "mihomo-anytls" {
			foundMihomoAnyTLS = true
		}
	}
	if !foundSingboxAnyTLS || !foundMihomoAnyTLS {
		t.Fatalf("expected domain mode AnyTLS defaults, got %+v", res.Node.Ports)
	}
	if !strings.Contains(strings.Join(res.Node.Links, "\n"), "anytls://") {
		t.Fatalf("expected AnyTLS connection link")
	}
}

func TestGenerateArtifactsNoDomainAutoDefaultsToReality(t *testing.T) {
	state := &AppState{
		cfg:        defaultConfig(),
		tokenUntil: make(map[string]time.Time),
	}
	req := InstallRequest{
		NodeName:   "ip-node",
		NodeIP:     "203.0.113.30",
		UseSingbox: boolPtr(true),
		UseMihomo:  boolPtr(true),
	}
	res, err := state.generateArtifacts(req)
	if err != nil {
		t.Fatalf("generate artifacts failed: %v", err)
	}
	foundReality := false
	foundAnyTLS := false
	for _, p := range res.Node.Ports {
		if p.ID == "singbox-vless-reality" || p.ID == "singbox-vless-reality-grpc" {
			foundReality = true
		}
		if p.ID == "singbox-anytls" || p.ID == "mihomo-anytls" {
			foundAnyTLS = true
		}
	}
	if !foundReality {
		t.Fatalf("expected no-domain mode to include Reality defaults, got %+v", res.Node.Ports)
	}
	if foundAnyTLS {
		t.Fatalf("did not expect no-domain mode to auto-select AnyTLS")
	}
}

func TestAllProtocolsHaveStrategyAndGenerateTemplates(t *testing.T) {
	state := &AppState{
		cfg:        defaultConfig(),
		tokenUntil: make(map[string]time.Time),
	}

	for idx, item := range protocolCatalog {
		if _, ok := protocolStrategyForID(item.ID); !ok {
			t.Fatalf("protocol strategy missing for %s", item.ID)
		}

		nodePortBase := 12000 + idx*17
		req := InstallRequest{
			NodeName:          "matrix-" + strings.ReplaceAll(item.ID, "-", "_"),
			NodeIP:            "203.0.113.10",
			UseSingbox:        boolPtr(true),
			UseMihomo:         boolPtr(true),
			PortBase:          nodePortBase,
			EnableBBR:         boolPtr(true),
			SelectedProtocols: []string{item.ID},
			AdminPassword:     "pass",
			ACMEDomain:        "edge.example.com",
			EnableACME:        boolPtr(false),
		}

		res, err := state.generateArtifacts(req)
		if err != nil {
			t.Fatalf("generateArtifacts failed for %s: %v", item.ID, err)
		}
		if !hasProtocolPort(res.Node.Ports, item.ID) {
			t.Fatalf("protocol %s not present in generated ports, got %+v", item.ID, res.Node.Ports)
		}
		if !strings.Contains(res.Shell, "# generated:") {
			t.Fatalf("shell script should include generation metadata for %s", item.ID)
		}
		if !strings.Contains(res.PS1, "Start-Service") {
			t.Fatalf("ps1 script should include service startup command for %s", item.ID)
		}
		if len(res.Node.Ports) == 0 {
			t.Fatalf("protocol %s should generate at least one port", item.ID)
		}
	}
}

func TestCLIProtocolCatalogIsComplete(t *testing.T) {
	state := &AppState{
		cfg:        defaultConfig(),
		tokenUntil: make(map[string]time.Time),
	}

	var out strings.Builder
	err := runCLI(state, &out, []string{"protocols"})
	if err != nil {
		t.Fatalf("runCLI protocols failed: %v", err)
	}

	var payload struct {
		Items []ProtocolCatalog `json:"items"`
	}
	if err := json.NewDecoder(strings.NewReader(out.String())).Decode(&payload); err != nil {
		t.Fatalf("decode cli protocols failed: %v", err)
	}
	if len(payload.Items) != len(protocolCatalog) {
		t.Fatalf("cli protocol catalog size mismatch, expect %d, got %d", len(protocolCatalog), len(payload.Items))
	}

	for _, item := range payload.Items {
		if item.ID == "" {
			t.Fatalf("cli protocol catalog contains empty id: %+v", item)
		}
	}
}

func hasProtocolPort(items []ProtocolPort, id string) bool {
	for _, p := range items {
		if p.ID == id {
			return true
		}
	}
	return false
}

func boolPtr(v bool) *bool {
	return &v
}
