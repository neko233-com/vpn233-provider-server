package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Task 4: provider generation produces a deployable NekoTLS endpoint.
func TestGenerateArtifactsNekoTLSNoDomainUsesReality(t *testing.T) {
	state := &AppState{cfg: defaultConfig(), tokenUntil: make(map[string]time.Time)}
	req := InstallRequest{
		NodeName:          "neko-ip",
		NodeIP:            "203.0.113.50",
		UseSingbox:        boolPtr(true),
		UseMihomo:         boolPtr(true),
		SelectedProtocols: []string{"mihomo-nekotls"},
	}
	res, err := state.generateArtifacts(req)
	if err != nil {
		t.Fatalf("generate artifacts failed: %v", err)
	}

	// mihomo-nekotls auto-pairs the matching singbox-nekotls on one shared port.
	if len(res.Node.Ports) != 2 {
		t.Fatalf("expected nekotls pair (2 entries), got %d: %+v", len(res.Node.Ports), res.Node.Ports)
	}
	if res.Node.Ports[0].Port != res.Node.Ports[1].Port {
		t.Fatalf("expected paired nekotls to share one port, got %+v", res.Node.Ports)
	}

	mihomoCfg, err := buildMihomoTemplate(res.profile, res.mapping)
	if err != nil {
		t.Fatalf("mihomo template failed: %v", err)
	}
	if !strings.Contains(mihomoCfg, "type: nekotls") {
		t.Fatalf("mihomo config should contain type: nekotls\n%s", mihomoCfg)
	}
	if !strings.Contains(mihomoCfg, "reality-opts:") {
		t.Fatalf("no-domain nekotls should use reality-opts\n%s", mihomoCfg)
	}
	if !strings.Contains(mihomoCfg, "padding-scheme: anytls") {
		t.Fatalf("nekotls should declare padding-scheme: anytls")
	}
	if strings.Contains(mihomoCfg, "ech-opts:") {
		t.Fatalf("no-domain nekotls should not emit ech-opts")
	}

	singCfg, err := buildSingBoxConfig(res.profile, res.mapping)
	if err != nil {
		t.Fatalf("singbox config failed: %v", err)
	}
	if !strings.Contains(singCfg, "\"anytls\"") {
		t.Fatalf("sing-box nekotls server should use native anytls inbound\n%s", singCfg)
	}
	if !strings.Contains(singCfg, "nekotls-") {
		t.Fatalf("sing-box nekotls inbound tag missing\n%s", singCfg)
	}

	if !strings.Contains(strings.Join(res.Node.Links, "\n"), "nekotls://") {
		t.Fatalf("expected nekotls:// connection link, got %v", res.Node.Links)
	}
}

// Task 4: domain mode flips NekoTLS to ECH with a real public name.
func TestGenerateArtifactsNekoTLSDomainUsesECH(t *testing.T) {
	state := &AppState{cfg: defaultConfig(), tokenUntil: make(map[string]time.Time)}
	req := InstallRequest{
		NodeName:          "neko-domain",
		NodeIP:            "edge.example.com",
		UseSingbox:        boolPtr(true),
		UseMihomo:         boolPtr(true),
		SelectedProtocols: []string{"mihomo-nekotls"},
	}
	res, err := state.generateArtifacts(req)
	if err != nil {
		t.Fatalf("generate artifacts failed: %v", err)
	}
	if res.profile.NekoTLSPublicName != "edge.example.com" {
		t.Fatalf("domain mode public name should be the domain, got %q", res.profile.NekoTLSPublicName)
	}
	mihomoCfg, err := buildMihomoTemplate(res.profile, res.mapping)
	if err != nil {
		t.Fatalf("mihomo template failed: %v", err)
	}
	if !strings.Contains(mihomoCfg, "ech-opts:") || !strings.Contains(mihomoCfg, "enable: true") {
		t.Fatalf("domain nekotls should enable ech-opts\n%s", mihomoCfg)
	}
	if strings.Contains(mihomoCfg, "reality-opts:") {
		t.Fatalf("domain nekotls should not emit reality-opts\n%s", mihomoCfg)
	}
	if !strings.Contains(mihomoCfg, "skip-cert-verify: false") {
		t.Fatalf("domain nekotls should verify the real certificate")
	}
}

// Task 4: the generated ECH config is a base64 ECHConfigList.
func TestNekoTLSECHConfigIsValidBase64(t *testing.T) {
	state := &AppState{cfg: defaultConfig(), tokenUntil: make(map[string]time.Time)}
	res, err := state.generateArtifacts(InstallRequest{
		NodeIP:            "edge.example.com",
		UseMihomo:         boolPtr(true),
		SelectedProtocols: []string{"mihomo-nekotls"},
	})
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(res.profile.NekoTLSECHConfig)
	if err != nil {
		t.Fatalf("ech config should be base64: %v", err)
	}
	if len(raw) < 4 {
		t.Fatalf("ech config too short: %d bytes", len(raw))
	}
	// ECHConfigList: uint16 length prefix matches the remainder.
	declared := int(raw[0])<<8 | int(raw[1])
	if declared != len(raw)-2 {
		t.Fatalf("ech config list length prefix %d != body %d", declared, len(raw)-2)
	}
}

// Task 6: everything the provider emits is loadable by the mihomo fork.
// DecodeNekoTLSOption mirrors the fork's structure-decode + validation step.
func TestNekoTLSForkConfigLoadingNoDomain(t *testing.T) {
	state := &AppState{cfg: defaultConfig(), tokenUntil: make(map[string]time.Time)}
	res, err := state.generateArtifacts(InstallRequest{
		NodeIP:            "203.0.113.51",
		UseMihomo:         boolPtr(true),
		SelectedProtocols: []string{"mihomo-nekotls"},
	})
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	loaded := 0
	for _, p := range res.mapping {
		if p.ID != "mihomo-nekotls" {
			continue
		}
		opt, decErr := DecodeNekoTLSOption(nekotlsProxyMap(res.profile, p.Port, mihomoProxyName(p)))
		if decErr != nil {
			t.Fatalf("fork failed to load nekotls proxy: %v", decErr)
		}
		if opt.Type != "nekotls" || opt.Port != p.Port {
			t.Fatalf("unexpected decoded option: %+v", opt)
		}
		if opt.RealityOpts == nil || opt.ECHOpts != nil {
			t.Fatalf("no-domain proxy must decode as reality, got %+v", opt)
		}
		loaded++
	}
	if loaded == 0 {
		t.Fatalf("no nekotls proxy was produced to load")
	}
}

func TestNekoTLSForkConfigLoadingDomain(t *testing.T) {
	state := &AppState{cfg: defaultConfig(), tokenUntil: make(map[string]time.Time)}
	res, err := state.generateArtifacts(InstallRequest{
		NodeIP:            "edge.example.com",
		UseMihomo:         boolPtr(true),
		SelectedProtocols: []string{"mihomo-nekotls"},
	})
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	for _, p := range res.mapping {
		if p.ID != "mihomo-nekotls" {
			continue
		}
		opt, decErr := DecodeNekoTLSOption(nekotlsProxyMap(res.profile, p.Port, mihomoProxyName(p)))
		if decErr != nil {
			t.Fatalf("fork failed to load domain nekotls proxy: %v", decErr)
		}
		if opt.ECHOpts == nil || !opt.ECHOpts.Enable || opt.ECHOpts.Config == "" {
			t.Fatalf("domain proxy must decode as ech-enabled, got %+v", opt.ECHOpts)
		}
		if opt.RealityOpts != nil {
			t.Fatalf("domain proxy must not carry reality-opts")
		}
	}
}

// Task 6: the fork loader rejects malformed proxies (invariant enforcement).
func TestDecodeNekoTLSOptionRejectsInvalid(t *testing.T) {
	cases := map[string]map[string]any{
		"missing-password": {
			"type": "nekotls", "server": "1.2.3.4", "port": 443, "sni": "x",
			"client-fingerprint": "chrome",
			"reality-opts":       map[string]any{"public-key": "k", "short-id": "s"},
		},
		"both-ech-and-reality": {
			"type": "nekotls", "server": "1.2.3.4", "port": 443, "password": "p", "sni": "x",
			"client-fingerprint": "chrome",
			"ech-opts":           map[string]any{"enable": true, "config": "abc"},
			"reality-opts":       map[string]any{"public-key": "k", "short-id": "s"},
		},
		"bad-port": {
			"type": "nekotls", "server": "1.2.3.4", "port": 0, "password": "p", "sni": "x",
			"client-fingerprint": "chrome",
			"reality-opts":       map[string]any{"public-key": "k", "short-id": "s"},
		},
		"wrong-type": {
			"type": "anytls", "server": "1.2.3.4", "port": 443, "password": "p", "sni": "x",
			"client-fingerprint": "chrome",
			"reality-opts":       map[string]any{"public-key": "k", "short-id": "s"},
		},
	}
	for name, mapping := range cases {
		if _, err := DecodeNekoTLSOption(mapping); err == nil {
			t.Fatalf("case %q: expected decode error, got nil", name)
		}
	}
}

// Task 6: a valid mapping decodes through the fork contract and round-trips to YAML.
func TestDecodeNekoTLSOptionAcceptsValidAndRenders(t *testing.T) {
	mapping := map[string]any{
		"name":               "nekotls-10000",
		"type":               "nekotls",
		"server":             "203.0.113.9",
		"port":               10000,
		"password":           "pw",
		"udp":                true,
		"sni":                "www.cloudflare.com",
		"alpn":               []string{"h2", "http/1.1"},
		"client-fingerprint": "chrome",
		"padding-scheme":     "anytls",
		"skip-cert-verify":   true,
		"reality-opts":       map[string]any{"public-key": "pk", "short-id": "sid"},
	}
	opt, err := DecodeNekoTLSOption(mapping)
	if err != nil {
		t.Fatalf("expected valid decode: %v", err)
	}
	if opt.Name != "nekotls-10000" || opt.Port != 10000 || opt.PaddingScheme != "anytls" {
		t.Fatalf("decoded option mismatch: %+v", opt)
	}
	yaml := strings.Join(renderNekoTLSYAMLLines(mapping), "\n")
	if !strings.Contains(yaml, "    type: nekotls") {
		t.Fatalf("rendered yaml missing type line:\n%s", yaml)
	}
	if !strings.Contains(yaml, "  - name: \"nekotls-10000\"") {
		t.Fatalf("rendered yaml missing name line:\n%s", yaml)
	}
}

// Sanity: float64 ports (as a real YAML/JSON decoder would yield) still load.
func TestDecodeNekoTLSOptionAcceptsFloatPort(t *testing.T) {
	var mapping map[string]any
	raw := `{"name":"n","type":"nekotls","server":"1.2.3.4","port":8443,"password":"p","sni":"x","client-fingerprint":"chrome","reality-opts":{"public-key":"k","short-id":"s"}}`
	if err := json.Unmarshal([]byte(raw), &mapping); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	opt, err := DecodeNekoTLSOption(mapping)
	if err != nil {
		t.Fatalf("expected decode of float port: %v", err)
	}
	if opt.Port != 8443 {
		t.Fatalf("expected port 8443, got %d", opt.Port)
	}
}
