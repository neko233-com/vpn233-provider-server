package tuic

import (
	"fmt"
	"github.com/neko233/vpn233-provider-server/internal/protocols/shared"
)

func Inbound(ctx shared.Context, port int) (map[string]any, error) {
	return map[string]any{
		"type":               "tuic",
		"tag":                shared.Tag("tuic", port),
		"listen":             "::",
		"listen_port":        port,
		"users":              []any{map[string]any{"uuid": ctx.UUID, "password": ctx.Password}},
		"congestion_control": "bbr",
		"zero_rtt_handshake": false,
		"tls":                shared.SingBoxTLSConfig(ctx, []string{"h3"}),
	}, nil
}

func ConnectionLink(ctx shared.Context, port int, name string) string {
	return fmt.Sprintf("tuic://%s:%s@%s:%d?sni=%s&congestion_control=bbr#%s", ctx.UUID, ctx.Password, ctx.NodeIP, port, ctx.ServerName, name)
}
