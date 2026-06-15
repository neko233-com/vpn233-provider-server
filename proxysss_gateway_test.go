package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testGatewayConfig() ServerConfig {
	cfg := defaultConfig()
	cfg.ProxySSS.Enabled = true
	cfg.ProxySSS.AdminURL = "http://127.0.0.1:7777"
	cfg.ProxySSS.BearerToken = "proxysss-token"
	cfg.ProxySSS.ProviderRouteName = "vpn233-provider-panel"
	cfg.ProxySSS.ProviderSubdomain = "panel"
	cfg.ProxySSS.Upstream = "http://127.0.0.1:8080"
	cfg.DNSAutomation.Enabled = true
	cfg.DNSAutomation.Provider = "cloudflare"
	cfg.DNSAutomation.APIToken = "cf-token"
	cfg.DNSAutomation.Email = "ops@example.com"
	cfg.DNSAutomation.BaseDomain = "example.com"
	cfg.DNSAutomation.Production = true
	cfg.DNSAutomation.Challenge = "dns01"
	cfg.DNSAutomation.CreateWildcard = true
	return cfg
}

func TestManagedDNSDomainsWithoutWildcardAddsProviderDomain(t *testing.T) {
	cfg := testGatewayConfig()
	cfg.DNSAutomation.CreateWildcard = false
	domains := managedDNSDomains(cfg, "panel.example.com")
	joined := strings.Join(domains, ",")
	if !strings.Contains(joined, "example.com") || !strings.Contains(joined, "panel.example.com") {
		t.Fatalf("expected example.com + panel.example.com, got %v", domains)
	}
}

func TestBuildProxySSSGatewayYAML(t *testing.T) {
	plan, err := buildProxySSSGatewayYAML(testGatewayConfig())
	if err != nil {
		t.Fatalf("buildProxySSSGatewayYAML failed: %v", err)
	}
	for _, needle := range []string{
		"mode: acme_managed",
		"challenge: dns01",
		"provider: cloudflare",
		"vpn233-provider-panel",
		"upstream: http://127.0.0.1:8080",
		"panel.example.com",
	} {
		if !strings.Contains(plan, needle) {
			t.Fatalf("gateway yaml missing %q:\n%s", needle, plan)
		}
	}
}

func TestRegisterProxySSSProviderRoute(t *testing.T) {
	cfg := testGatewayConfig()
	var gotAuth string
	var gotPath string
	var gotPayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"persisted":true}`))
	}))
	defer server.Close()
	cfg.ProxySSS.AdminURL = server.URL
	result, err := registerProxySSSProviderRoute(server.Client(), cfg)
	if err != nil {
		t.Fatalf("registerProxySSSProviderRoute failed: %v", err)
	}
	if gotAuth != "Bearer proxysss-token" {
		t.Fatalf("unexpected auth header: %q", gotAuth)
	}
	if gotPath != "/v1/domain-routes/upsert" {
		t.Fatalf("unexpected path: %q", gotPath)
	}
	if gotPayload["name"] != "vpn233-provider-panel" || gotPayload["upstream"] != "http://127.0.0.1:8080" {
		t.Fatalf("unexpected payload: %+v", gotPayload)
	}
	if result["ok"] != true {
		t.Fatalf("expected ok=true, got %+v", result)
	}
}

func TestGatewayHandlers(t *testing.T) {
	cfg := testGatewayConfig()
	registerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer registerServer.Close()
	cfg.ProxySSS.AdminURL = registerServer.URL
	state := &AppState{cfgPath: filepath.Join(t.TempDir(), defaultServerConfigFile), cfg: cfg, tokenUntil: make(map[string]time.Time)}

	planReq := httptest.NewRequest(http.MethodGet, "/api/v1/gateway/proxysss.yaml", nil)
	planRec := httptest.NewRecorder()
	state.proxySSSGatewayYAMLHandler(planRec, planReq)
	if planRec.Code != http.StatusOK {
		t.Fatalf("gateway yaml handler: expect 200, got %d body=%s", planRec.Code, planRec.Body.String())
	}
	if !strings.Contains(planRec.Body.String(), "provider: cloudflare") {
		t.Fatalf("gateway yaml handler missing provider line")
	}

	registerReq := httptest.NewRequest(http.MethodPost, "/api/v1/gateway/register", nil)
	registerRec := httptest.NewRecorder()
	state.proxySSSRegisterHandler(registerRec, registerReq)
	if registerRec.Code != http.StatusOK {
		t.Fatalf("gateway register handler: expect 200, got %d body=%s", registerRec.Code, registerRec.Body.String())
	}
	if !strings.Contains(registerRec.Body.String(), "vpn233-provider-panel") {
		t.Fatalf("gateway register handler missing route name: %s", registerRec.Body.String())
	}
}
