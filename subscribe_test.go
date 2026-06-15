package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Task 5: clash-meta-nekotls always yields a forked-mihomo config with nekotls.
func TestSubscribeConvertClashMetaNekoTLS(t *testing.T) {
	state := &AppState{cfg: defaultConfig(), tokenUntil: make(map[string]time.Time)}
	body, contentType, err := state.buildSubscriptionArtifact(InstallRequest{NodeIP: "203.0.113.60"}, subscribeTargetClashMetaNekoTLS)
	if err != nil {
		t.Fatalf("convert failed: %v", err)
	}
	if !strings.Contains(contentType, "yaml") {
		t.Fatalf("expected yaml content type, got %q", contentType)
	}
	if !strings.Contains(body, "type: nekotls") {
		t.Fatalf("clash-meta-nekotls output must contain type: nekotls\n%s", body)
	}
	if !strings.Contains(body, "proxy-groups:") {
		t.Fatalf("expected a complete clash-meta document")
	}
}

// Task 5: stock clash targets downgrade nekotls -> anytls so they still parse.
func TestSubscribeConvertClashSubstitutesAnyTLS(t *testing.T) {
	state := &AppState{cfg: defaultConfig(), tokenUntil: make(map[string]time.Time)}
	body, _, err := state.buildSubscriptionArtifact(InstallRequest{
		NodeIP:            "203.0.113.61",
		SelectedProtocols: []string{"mihomo-nekotls"},
	}, subscribeTargetClash)
	if err != nil {
		t.Fatalf("convert failed: %v", err)
	}
	if strings.Contains(body, "type: nekotls") {
		t.Fatalf("stock clash output must not contain type: nekotls\n%s", body)
	}
	if !strings.Contains(body, "type: anytls") {
		t.Fatalf("stock clash output should downgrade to type: anytls\n%s", body)
	}
}

// Task 5: sing-box target returns a valid JSON config.
func TestSubscribeConvertSingBox(t *testing.T) {
	state := &AppState{cfg: defaultConfig(), tokenUntil: make(map[string]time.Time)}
	body, contentType, err := state.buildSubscriptionArtifact(InstallRequest{
		NodeIP:            "203.0.113.62",
		SelectedProtocols: []string{"singbox-nekotls"},
	}, subscribeTargetSingBox)
	if err != nil {
		t.Fatalf("convert failed: %v", err)
	}
	if !strings.Contains(contentType, "json") {
		t.Fatalf("expected json content type, got %q", contentType)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("sing-box output must be valid json: %v", err)
	}
	if _, ok := parsed["inbounds"]; !ok {
		t.Fatalf("sing-box output should contain inbounds")
	}
}

// Task 5: links target returns nekotls:// share links.
func TestSubscribeConvertLinks(t *testing.T) {
	state := &AppState{cfg: defaultConfig(), tokenUntil: make(map[string]time.Time)}
	body, _, err := state.buildSubscriptionArtifact(InstallRequest{
		NodeIP:            "203.0.113.63",
		SelectedProtocols: []string{"mihomo-nekotls"},
	}, subscribeTargetLinks)
	if err != nil {
		t.Fatalf("convert failed: %v", err)
	}
	if !strings.Contains(body, "nekotls://") {
		t.Fatalf("links output should contain a nekotls:// link\n%s", body)
	}
}

func TestSubscribeConvertUnsupportedTarget(t *testing.T) {
	state := &AppState{cfg: defaultConfig(), tokenUntil: make(map[string]time.Time)}
	if _, _, err := state.buildSubscriptionArtifact(InstallRequest{NodeIP: "1.2.3.4"}, "deno"); err == nil {
		t.Fatalf("expected unsupported target error")
	}
}

// Task 5: the HTTP endpoint serves the converted document end to end.
func TestSubscribeConvertHandlerDefaultsToNekoTLS(t *testing.T) {
	state := &AppState{cfg: defaultConfig(), tokenUntil: make(map[string]time.Time)}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/subscribe/convert?node_ip=203.0.113.64", nil)
	rec := httptest.NewRecorder()
	state.subscribeConvertHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expect 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("X-Subscribe-Target"); got != subscribeTargetClashMetaNekoTLS {
		t.Fatalf("expected default target header, got %q", got)
	}
	if !strings.Contains(rec.Body.String(), "type: nekotls") {
		t.Fatalf("default convert should emit nekotls")
	}
}

func TestSubscribeConvertHandlerRejectsBadTarget(t *testing.T) {
	state := &AppState{cfg: defaultConfig(), tokenUntil: make(map[string]time.Time)}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/subscribe/convert?target=quantumult&node_ip=1.2.3.4", nil)
	rec := httptest.NewRecorder()
	state.subscribeConvertHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expect 400 for unsupported target, got %d", rec.Code)
	}
}

func TestSubscribeConvertHandlerTokenMismatch(t *testing.T) {
	state := &AppState{
		cfg:        normalizeRepoDefaults(ServerConfig{SubscribeVerifyToken: "secret"}),
		tokenUntil: make(map[string]time.Time),
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/subscribe/convert?token=wrong&node_ip=1.2.3.4", nil)
	rec := httptest.NewRecorder()
	state.subscribeConvertHandler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expect 401 on token mismatch, got %d", rec.Code)
	}
}

// Task 3: the verify endpoint advertises the new conversion targets.
func TestSubscribeTargetsIncludesClashMetaNekoTLS(t *testing.T) {
	found := false
	for _, target := range subscribeTargets() {
		if target == subscribeTargetClashMetaNekoTLS {
			found = true
		}
	}
	if !found {
		t.Fatalf("subscribe targets must advertise clash-meta-nekotls: %v", subscribeTargets())
	}
}
