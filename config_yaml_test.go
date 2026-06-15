package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfigMigratesLegacyJSONToServerYAML(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, legacyServerConfigFile)
	serverPath := filepath.Join(dir, defaultServerConfigFile)
	legacyJSON := `{
  "listen_addr":"127.0.0.1",
  "listen_port":19090,
  "admin_user":"ops",
  "admin_password":"secret",
  "default_data_dir":"/srv/vpn233",
  "default_use_singbox":false,
  "subscribe_repo_url":"https://example.com/sub.git"
}`
	if err := os.WriteFile(legacyPath, []byte(legacyJSON), 0o644); err != nil {
		t.Fatalf("write legacy json: %v", err)
	}
	state := &AppState{cfgPath: serverPath, cfg: defaultConfig(), tokenUntil: make(map[string]time.Time)}
	if err := state.loadConfig(); err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}
	cfg := state.snapshotConfig()
	if cfg.ListenPort != 19090 || cfg.AdminUser != "ops" || cfg.DefaultDataDir != "/srv/vpn233" {
		t.Fatalf("legacy values not migrated: %+v", cfg)
	}
	if cfg.DefaultUseSingbox {
		t.Fatalf("expected explicit false to survive migration")
	}
	raw, err := os.ReadFile(serverPath)
	if err != nil {
		t.Fatalf("expected migrated server.yaml to exist: %v", err)
	}
	if !strings.Contains(string(raw), "listen_addr: 127.0.0.1") && !strings.Contains(string(raw), "listen_addr: \"127.0.0.1\"") {
		t.Fatalf("migrated file does not look like YAML:\n%s", raw)
	}
}

func TestSaveConfigWritesYAML(t *testing.T) {
	state := &AppState{cfgPath: filepath.Join(t.TempDir(), defaultServerConfigFile), cfg: defaultConfig(), tokenUntil: make(map[string]time.Time)}
	state.cfg.ProxySSS.Enabled = true
	state.cfg.DNSAutomation.Enabled = true
	state.cfg.DNSAutomation.Provider = "cloudflare"
	state.cfg.DNSAutomation.APIToken = "token"
	state.cfg.DNSAutomation.Email = "ops@example.com"
	state.cfg.DNSAutomation.BaseDomain = "example.com"
	if err := state.saveConfig(); err != nil {
		t.Fatalf("saveConfig failed: %v", err)
	}
	raw, err := os.ReadFile(state.cfgPath)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	text := string(raw)
	for _, needle := range []string{"listen_addr:", "proxysss:", "dns_automation:", "provider: cloudflare"} {
		if !strings.Contains(text, needle) {
			t.Fatalf("saved YAML missing %q:\n%s", needle, text)
		}
	}
	if strings.Contains(text, "{\n") {
		t.Fatalf("config should no longer be JSON:\n%s", text)
	}
}

func TestConfigHandlerReturnsServerYAMLMetadata(t *testing.T) {
	state := &AppState{cfgPath: filepath.Join(t.TempDir(), defaultServerConfigFile), cfg: defaultConfig(), tokenUntil: make(map[string]time.Time)}
	state.cfg.ProxySSS.Enabled = true
	state.cfg.DNSAutomation.Enabled = true
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	rec := httptest.NewRecorder()
	state.configHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expect 200, got %d", rec.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode config response: %v", err)
	}
	if body["config_format"] != defaultServerConfigFile {
		t.Fatalf("expected config_format=%q, got %v", defaultServerConfigFile, body["config_format"])
	}
	if _, ok := body["proxysss"].(map[string]any); !ok {
		t.Fatalf("expected proxysss block in response, got %T", body["proxysss"])
	}
	if _, ok := body["dns_automation"].(map[string]any); !ok {
		t.Fatalf("expected dns_automation block in response, got %T", body["dns_automation"])
	}
}

func TestConfigHandlerPostCanDisableProxySSSAndDNS(t *testing.T) {
	state := &AppState{cfgPath: filepath.Join(t.TempDir(), defaultServerConfigFile), cfg: defaultConfig(), tokenUntil: make(map[string]time.Time)}
	state.cfg.ProxySSS.Enabled = true
	state.cfg.ProxySSS.AdminURL = "http://127.0.0.1:7777"
	state.cfg.DNSAutomation.Enabled = true
	state.cfg.DNSAutomation.Provider = "cloudflare"
	body := `{"proxysss":{"enabled":false},"dns_automation":{"enabled":false},"default_use_singbox":false}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/config", strings.NewReader(body))
	rec := httptest.NewRecorder()
	state.configHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expect 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	cfg := state.snapshotConfig()
	if cfg.ProxySSS.Enabled {
		t.Fatalf("expected proxysss to be disabled, got %+v", cfg.ProxySSS)
	}
	if cfg.DNSAutomation.Enabled {
		t.Fatalf("expected dns automation to be disabled, got %+v", cfg.DNSAutomation)
	}
	if cfg.DefaultUseSingbox {
		t.Fatalf("expected explicit default_use_singbox=false to persist")
	}
}
