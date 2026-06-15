package vmess_ws

import (
	"github.com/neko233/vpn233-provider-server/internal/protocols/shared"
)

func Inbound(ctx shared.Context, port int) (map[string]any, error) {
	return map[string]any{
		"type":        "vmess",
		"tag":         shared.Tag("vmess-ws", port),
		"listen":      "::",
		"listen_port": port,
		"users": []any{
			map[string]any{
				"uuid":    ctx.UUID,
				"alterId": 0,
			},
		},
		"tls":       shared.SingBoxTLSConfig(ctx, []string{"http/1.1"}),
		"transport": shared.WSTransport("/vpn233-vmess", ctx.ServerName),
	}, nil
}

func ConnectionLink(ctx shared.Context, port int, name string) string {
	return shared.VMessLink(ctx.NodeIP, port, ctx.UUID, "/vpn233-vmess", ctx.ServerName, true) + "#" + name
}
