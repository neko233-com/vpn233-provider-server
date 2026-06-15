package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
)

// NekoTLS is the neko233 house proxy protocol.
//
// Wire model: an AnyTLS-compatible stream over TLS 1.3, so a stock sing-box
// `anytls` inbound can already serve it (deployable today). The forked mihomo
// `type: nekotls` outbound adds the camouflage layer that no upstream core
// exposes as a single composite:
//   - uTLS Chrome ClientHello fingerprint
//   - ECH (Encrypted Client Hello) for SNI concealment in domain mode
//   - Reality-style handshake borrowing for no-domain (IP) mode
//   - AnyTLS padding scheme + session multiplexing
//
// This file is the single source of truth shared by:
//   - the provider generator (sing-box inbound + mihomo outbound + links)
//   - the subscribe converter (clash-meta-nekotls target)
//   - the mihomo-fork loader contract (NekoTLSOption + DecodeNekoTLSOption)
const (
	nekotlsProtocolType  = "nekotls"
	nekotlsPaddingScheme = "anytls"
	nekotlsFingerprint   = "chrome"
)

func nekotlsALPN() []string { return []string{"h2", "http/1.1"} }

// NekoTLSOption is the outbound option schema for mihomo `type: nekotls`.
//
// The forked mihomo MUST decode a proxy mapping into this struct (mihomo turns
// YAML into map[string]any, then structmaps it via its `structure` package).
// DecodeNekoTLSOption below mirrors that decode step so the provider can prove,
// in CI, that everything it emits is loadable by the fork.
type NekoTLSOption struct {
	Name              string                 `yaml:"name"`
	Type              string                 `yaml:"type"`
	Server            string                 `yaml:"server"`
	Port              int                    `yaml:"port"`
	Password          string                 `yaml:"password"`
	UDP               bool                   `yaml:"udp,omitempty"`
	SNI               string                 `yaml:"sni,omitempty"`
	ALPN              []string               `yaml:"alpn,omitempty"`
	ClientFingerprint string                 `yaml:"client-fingerprint,omitempty"`
	PaddingScheme     string                 `yaml:"padding-scheme,omitempty"`
	SkipCertVerify    bool                   `yaml:"skip-cert-verify,omitempty"`
	ECHOpts           *NekoTLSECHOptions     `yaml:"ech-opts,omitempty"`
	RealityOpts       *NekoTLSRealityOptions `yaml:"reality-opts,omitempty"`
}

// NekoTLSECHOptions configures Encrypted Client Hello (domain mode).
type NekoTLSECHOptions struct {
	Enable bool   `yaml:"enable"`
	Config string `yaml:"config"`
}

// NekoTLSRealityOptions configures the Reality fallback (no-domain mode).
type NekoTLSRealityOptions struct {
	PublicKey string `yaml:"public-key"`
	ShortID   string `yaml:"short-id"`
}

// nekotlsDomainMode reports whether the node should run NekoTLS in domain mode
// (real SNI + ECH) versus no-domain mode (Reality handshake borrowing).
func nekotlsDomainMode(req normalizedRequest) bool {
	return endpointStrategy(req.NodeIP) == "domain"
}

// nekotlsProxyMap builds the canonical proxy mapping for one NekoTLS endpoint.
// This map is exactly what the forked mihomo would receive after YAML decode,
// and is rendered verbatim into both the mihomo config and subscribe output.
func nekotlsProxyMap(req normalizedRequest, port int, name string) map[string]any {
	m := map[string]any{
		"name":               name,
		"type":               nekotlsProtocolType,
		"server":             req.NodeIP,
		"port":               port,
		"password":           req.Password,
		"udp":                true,
		"alpn":               nekotlsALPN(),
		"client-fingerprint": nekotlsFingerprint,
		"padding-scheme":     nekotlsPaddingScheme,
	}
	if nekotlsDomainMode(req) {
		m["sni"] = req.NekoTLSPublicName
		m["skip-cert-verify"] = false
		m["ech-opts"] = map[string]any{
			"enable": true,
			"config": req.NekoTLSECHConfig,
		}
	} else {
		m["sni"] = req.RealityServer
		m["skip-cert-verify"] = true
		m["reality-opts"] = map[string]any{
			"public-key": req.RealityPublicKey,
			"short-id":   req.RealityShortID,
		}
	}
	return m
}

// renderNekoTLSYAMLLines renders a NekoTLS proxy map into deterministic
// clash-meta YAML lines (fixed key order, list-item indentation).
func renderNekoTLSYAMLLines(m map[string]any) []string {
	lines := []string{
		fmt.Sprintf("  - name: %s", yamlQuote(toStringValue(m["name"]))),
		fmt.Sprintf("    type: %s", nekotlsProtocolType),
		fmt.Sprintf("    server: %s", yamlQuote(toStringValue(m["server"]))),
		fmt.Sprintf("    port: %d", toIntValueOrZero(m["port"])),
		fmt.Sprintf("    password: %s", yamlQuote(toStringValue(m["password"]))),
		"    udp: true",
		fmt.Sprintf("    sni: %s", yamlQuote(toStringValue(m["sni"]))),
		"    alpn:",
	}
	for _, alpn := range toStringSlice(m["alpn"]) {
		lines = append(lines, fmt.Sprintf("      - %s", alpn))
	}
	lines = append(lines,
		fmt.Sprintf("    client-fingerprint: %s", toStringValue(m["client-fingerprint"])),
		fmt.Sprintf("    padding-scheme: %s", toStringValue(m["padding-scheme"])),
		fmt.Sprintf("    skip-cert-verify: %t", toBoolValue(m["skip-cert-verify"])),
	)
	if ech, ok := m["ech-opts"].(map[string]any); ok {
		lines = append(lines,
			"    ech-opts:",
			fmt.Sprintf("      enable: %t", toBoolValue(ech["enable"])),
			fmt.Sprintf("      config: %s", yamlQuote(toStringValue(ech["config"]))),
		)
	}
	if reality, ok := m["reality-opts"].(map[string]any); ok {
		lines = append(lines,
			"    reality-opts:",
			fmt.Sprintf("      public-key: %s", yamlQuote(toStringValue(reality["public-key"]))),
			fmt.Sprintf("      short-id: %s", yamlQuote(toStringValue(reality["short-id"]))),
		)
	}
	return lines
}

// DecodeNekoTLSOption mirrors the forked mihomo loader: it turns a decoded YAML
// proxy mapping (map[string]any) into a typed NekoTLSOption. The provider uses
// this to prove its generated configs are loadable by the fork.
func DecodeNekoTLSOption(m map[string]any) (NekoTLSOption, error) {
	if m == nil {
		return NekoTLSOption{}, errors.New("nekotls: empty proxy mapping")
	}
	opt := NekoTLSOption{
		Name:              toStringValue(m["name"]),
		Type:              toStringValue(m["type"]),
		Server:            toStringValue(m["server"]),
		Password:          toStringValue(m["password"]),
		UDP:               toBoolValue(m["udp"]),
		SNI:               toStringValue(m["sni"]),
		ALPN:              toStringSlice(m["alpn"]),
		ClientFingerprint: toStringValue(m["client-fingerprint"]),
		PaddingScheme:     toStringValue(m["padding-scheme"]),
		SkipCertVerify:    toBoolValue(m["skip-cert-verify"]),
	}
	if port, ok := toIntValue(m["port"]); ok {
		opt.Port = port
	}
	if ech, ok := m["ech-opts"].(map[string]any); ok {
		opt.ECHOpts = &NekoTLSECHOptions{
			Enable: toBoolValue(ech["enable"]),
			Config: toStringValue(ech["config"]),
		}
	}
	if reality, ok := m["reality-opts"].(map[string]any); ok {
		opt.RealityOpts = &NekoTLSRealityOptions{
			PublicKey: toStringValue(reality["public-key"]),
			ShortID:   toStringValue(reality["short-id"]),
		}
	}
	if err := opt.Validate(); err != nil {
		return NekoTLSOption{}, err
	}
	return opt, nil
}

// Validate enforces the NekoTLS schema invariants the fork relies on.
func (o NekoTLSOption) Validate() error {
	if o.Type != nekotlsProtocolType {
		return fmt.Errorf("nekotls: type must be %q, got %q", nekotlsProtocolType, o.Type)
	}
	if o.Server == "" {
		return errors.New("nekotls: server is required")
	}
	if o.Port <= 0 || o.Port > 65535 {
		return fmt.Errorf("nekotls: port out of range: %d", o.Port)
	}
	if o.Password == "" {
		return errors.New("nekotls: password is required")
	}
	if o.SNI == "" {
		return errors.New("nekotls: sni is required")
	}
	if o.ClientFingerprint == "" {
		return errors.New("nekotls: client-fingerprint is required")
	}
	echEnabled := o.ECHOpts != nil && o.ECHOpts.Enable
	realityEnabled := o.RealityOpts != nil
	if echEnabled == realityEnabled {
		return errors.New("nekotls: exactly one of ech-opts(enabled) or reality-opts must be set")
	}
	if echEnabled && o.ECHOpts.Config == "" {
		return errors.New("nekotls: ech-opts.config is required when ech is enabled")
	}
	if realityEnabled && (o.RealityOpts.PublicKey == "" || o.RealityOpts.ShortID == "") {
		return errors.New("nekotls: reality-opts requires public-key and short-id")
	}
	return nil
}

// singBoxNekoTLSInbound builds a runnable sing-box server side for NekoTLS.
// Stock sing-box has no `nekotls` type, so the deployable server uses its
// native `anytls` inbound (the NekoTLS outer wire) plus TLS material.
func singBoxNekoTLSInbound(req normalizedRequest, p ProtocolPort) map[string]any {
	return map[string]any{
		"type":        "anytls",
		"tag":         fmt.Sprintf("nekotls-%d", p.Port),
		"listen":      "::",
		"listen_port": p.Port,
		"users": []any{
			map[string]any{
				"name":     "vpn233",
				"password": req.Password,
			},
		},
		"padding_scheme": []string{},
		"tls":            singBoxTLSConfig(req, nekotlsALPN()),
	}
}

// nekotlsLink builds a shareable nekotls:// connection URI.
func nekotlsLink(req normalizedRequest, p ProtocolPort) string {
	link := fmt.Sprintf("nekotls://%s@%s:%d/?fp=%s&padding=%s",
		url.QueryEscape(req.Password), req.NodeIP, p.Port, nekotlsFingerprint, nekotlsPaddingScheme)
	if nekotlsDomainMode(req) {
		link += "&sni=" + url.QueryEscape(req.NekoTLSPublicName)
		link += "&ech=" + url.QueryEscape(req.NekoTLSECHConfig)
	} else {
		link += "&sni=" + url.QueryEscape(req.RealityServer)
		link += "&pbk=" + url.QueryEscape(req.RealityPublicKey)
		link += "&sid=" + url.QueryEscape(req.RealityShortID)
	}
	return link + "#" + p.Name
}

// generateNekoTLSECHConfig builds a structurally valid ECHConfigList (draft-ietf
// TLS ESNI) carrying a freshly generated X25519 HPKE public key. The forked
// keygen finalizes the matching private key on the server; the provider only
// needs to emit a loadable config blob for the client side.
func generateNekoTLSECHConfig(publicName string) (string, error) {
	if publicName == "" {
		publicName = "vpn233.local"
	}
	if len(publicName) > 255 {
		publicName = publicName[:255]
	}
	curve := ecdh.X25519()
	key, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	pub := key.PublicKey().Bytes()

	var contents bytes.Buffer
	contents.WriteByte(0x01)                 // config_id
	contents.Write([]byte{0x00, 0x20})       // kem_id: DHKEM(X25519, HKDF-SHA256)
	contents.Write(uint16Bytes(len(pub)))    // public_key length
	contents.Write(pub)                      // public_key
	suites := []byte{0x00, 0x01, 0x00, 0x01} // HKDF-SHA256 + AES-128-GCM
	contents.Write(uint16Bytes(len(suites)))
	contents.Write(suites)
	contents.WriteByte(0x40)                  // maximum_name_length
	contents.WriteByte(byte(len(publicName))) // public_name length
	contents.WriteString(publicName)          // public_name
	contents.Write([]byte{0x00, 0x00})        // extensions (empty)

	var echConfig bytes.Buffer
	echConfig.Write([]byte{0xfe, 0x0d}) // version: draft-13 (0xfe0d)
	echConfig.Write(uint16Bytes(contents.Len()))
	echConfig.Write(contents.Bytes())

	var list bytes.Buffer
	list.Write(uint16Bytes(echConfig.Len()))
	list.Write(echConfig.Bytes())
	return base64.StdEncoding.EncodeToString(list.Bytes()), nil
}

func uint16Bytes(n int) []byte {
	return []byte{byte(n >> 8), byte(n)}
}

func toStringValue(v any) string {
	s, _ := v.(string)
	return s
}

func toBoolValue(v any) bool {
	b, _ := v.(bool)
	return b
}

func toIntValue(v any) (int, bool) {
	switch t := v.(type) {
	case int:
		return t, true
	case int64:
		return int(t), true
	case float64:
		return int(t), true
	default:
		return 0, false
	}
}

func toIntValueOrZero(v any) int {
	n, _ := toIntValue(v)
	return n
}

func toStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
