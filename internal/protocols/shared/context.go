package shared

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
)

type Context struct {
	NodeIP                    string
	ServerName                string
	DataDir                   string
	Password                  string
	UUID                      string
	GRPCServiceName           string
	RealityPrivateKey         string
	RealityPublicKey          string
	RealityShortID            string
	RealityServer             string
	WireGuardServerPrivateKey string
	WireGuardServerPublicKey  string
	WireGuardClientPrivateKey string
	WireGuardClientPublicKey  string
	WireGuardServerCIDR       string
	WireGuardClientCIDR       string
	WireGuardPresharedKey     string
	NekoTLSPublicName         string
	NekoTLSECHConfig          string
}

func YamlQuote(raw string) string {
	return strconv.Quote(raw)
}

func Tag(prefix string, port int) string {
	return fmt.Sprintf("%s-%d", prefix, port)
}

func SingBoxInboundVLESS(port int, uuid string) map[string]any {
	return map[string]any{
		"type":        "vless",
		"tag":         Tag("vless", port),
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

func SingBoxTLSConfig(ctx Context, alpn []string) map[string]any {
	cfg := map[string]any{
		"enabled":          true,
		"server_name":      ctx.ServerName,
		"certificate_path": filepath.ToSlash(filepath.Join(ctx.DataDir, "tls", "server.crt")),
		"key_path":         filepath.ToSlash(filepath.Join(ctx.DataDir, "tls", "server.key")),
	}
	if len(alpn) > 0 {
		cfg["alpn"] = alpn
	}
	return cfg
}

func SingBoxRealityConfig(ctx Context, alpn []string) map[string]any {
	cfg := map[string]any{
		"enabled":     true,
		"server_name": ctx.RealityServer,
		"reality": map[string]any{
			"enabled":             true,
			"private_key":         ctx.RealityPrivateKey,
			"short_id":            []string{ctx.RealityShortID},
			"max_time_difference": "10s",
			"handshake": map[string]any{
				"server":      ctx.RealityServer,
				"server_port": 443,
			},
		},
	}
	if len(alpn) > 0 {
		cfg["alpn"] = alpn
	}
	return cfg
}

func GRPCTransport(serviceName string) map[string]any {
	return map[string]any{
		"type":                  "grpc",
		"service_name":          serviceName,
		"idle_timeout":          "15s",
		"permit_without_stream": false,
	}
}

func WSTransport(pathValue string, host string) map[string]any {
	return map[string]any{
		"type": "ws",
		"path": pathValue,
		"headers": map[string]any{
			"Host": host,
		},
	}
}

func VMessLink(host string, port int, uuid, pathValue, serverName string, tlsEnabled bool) string {
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

func trimSlash(raw string) string {
	if len(raw) == 0 {
		return ""
	}
	if raw == "/" {
		return ""
	}
	for len(raw) > 1 && raw[len(raw)-1] == '/' {
		raw = raw[:len(raw)-1]
	}
	return raw
}

func readBytes(n int) ([]byte, error) {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}
