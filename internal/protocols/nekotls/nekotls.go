package nekotls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
)

// NekoTLS is the neko233 house proxy protocol implementation.
//
// The server side is emitted as a stock sing-box anytls inbound, while client
// side templates use `type: nekotls` as a strategy envelope.
const (
	ProtocolType  = "nekotls"
	singboxInboundType = "anytls"
	paddingScheme = "anytls"
	fingerprint   = "chrome"
)

// Context is the normalized render context shared by all NekoTLS templates.
type Context struct {
	NodeIP            string
	ServerName        string
	DataDir           string
	Password          string
	RealityServer     string
	RealityPublicKey  string
	RealityShortID    string
	NekoTLSPublicName string
	NekoTLSECHConfig  string
	DomainMode        bool
}

// NekoTLSOption is the outbound option schema for mihomo `type: nekotls`.
//
// It mirrors the forked mihomo decode contract used by this provider in tests.
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

func ALPN() []string {
	return []string{"h2", "http/1.1"}
}

func Fingerprint() string {
	return fingerprint
}

// SingBoxInbound builds a runnable sing-box server side for NekoTLS.
func SingBoxInbound(ctx Context, port int) map[string]any {
	return map[string]any{
		"type":        singboxInboundType,
		"tag":         fmt.Sprintf("nekotls-%d", port),
		"listen":      "::",
		"listen_port": port,
		"users": []any{
			map[string]any{
				"name":     "vpn233",
				"password": ctx.Password,
			},
		},
		"padding_scheme": []string{},
	}
}

// ProxyMap builds canonical mihomo fork proxy mapping for NekoTLS.
func ProxyMap(ctx Context, port int, name string) map[string]any {
	m := map[string]any{
		"name":               name,
		"type":               ProtocolType,
		"server":             ctx.NodeIP,
		"port":               port,
		"password":           ctx.Password,
		"udp":                true,
		"alpn":               ALPN(),
		"client-fingerprint": fingerprint,
		"padding-scheme":     paddingScheme,
	}
	if ctx.DomainMode {
		m["sni"] = ctx.NekoTLSPublicName
		m["skip-cert-verify"] = false
		m["ech-opts"] = map[string]any{
			"enable": true,
			"config": ctx.NekoTLSECHConfig,
		}
	} else {
		m["sni"] = ctx.RealityServer
		m["skip-cert-verify"] = true
		m["reality-opts"] = map[string]any{
			"public-key": ctx.RealityPublicKey,
			"short-id":   ctx.RealityShortID,
		}
	}
	return m
}

// RenderYAMLLines renders a proxy map into deterministic clash-meta yaml snippet.
func RenderYAMLLines(m map[string]any) []string {
	lines := []string{
		fmt.Sprintf("  - name: %s", yamlQuote(toStringValue(m["name"]))),
		fmt.Sprintf("    type: %s", ProtocolType),
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

func BuildLink(ctx Context, port int, name string) string {
	link := fmt.Sprintf("nekotls://%s@%s:%d/?fp=%s&padding=%s",
		url.QueryEscape(ctx.Password), ctx.NodeIP, port, fingerprint, paddingScheme)
	if ctx.DomainMode {
		link += "&sni=" + url.QueryEscape(ctx.NekoTLSPublicName)
		link += "&ech=" + url.QueryEscape(ctx.NekoTLSECHConfig)
	} else {
		link += "&sni=" + url.QueryEscape(ctx.RealityServer)
		link += "&pbk=" + url.QueryEscape(ctx.RealityPublicKey)
		link += "&sid=" + url.QueryEscape(ctx.RealityShortID)
	}
	return link + "#" + name
}

// GenerateECHConfig builds a minimal structurally valid ECHConfigList with key material.
func GenerateECHConfig(publicName string) (string, error) {
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
	contents.WriteByte(0x01)
	contents.Write([]byte{0x00, 0x20})
	contents.Write(uint16Bytes(len(pub)))
	contents.Write(pub)
	suites := []byte{0x00, 0x01, 0x00, 0x01}
	contents.Write(uint16Bytes(len(suites)))
	contents.Write(suites)
	contents.WriteByte(0x40)
	contents.WriteByte(byte(len(publicName)))
	contents.WriteString(publicName)
	contents.Write([]byte{0x00, 0x00})

	var echConfig bytes.Buffer
	echConfig.Write([]byte{0xfe, 0x0d})
	echConfig.Write(uint16Bytes(contents.Len()))
	echConfig.Write(contents.Bytes())

	var list bytes.Buffer
	list.Write(uint16Bytes(echConfig.Len()))
	list.Write(echConfig.Bytes())
	return base64.StdEncoding.EncodeToString(list.Bytes()), nil
}

// DecodeOption enforces schema invariants and mirrors forked mihomo decode.
func DecodeOption(m map[string]any) (NekoTLSOption, error) {
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

func (o NekoTLSOption) Validate() error {
	if o.Type != ProtocolType {
		return fmt.Errorf("nekotls: type must be %q, got %q", ProtocolType, o.Type)
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

func yamlQuote(value string) string {
	if value == "" {
		return "\"\""
	}
	safe := []byte{'"'}
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '"', '\\':
			safe = append(safe, '\\', value[i])
		default:
			safe = append(safe, value[i])
		}
	}
	safe = append(safe, '"')
	return string(safe)
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

func uint16Bytes(n int) []byte {
	return []byte{byte(n >> 8), byte(n)}
}
