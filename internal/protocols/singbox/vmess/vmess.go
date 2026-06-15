package vmess

import (
	"github.com/neko233/vpn233-provider-server/internal/protocols/shared"
)

func Inbound(ctx shared.Context, port int) (map[string]any, error) {
	return map[string]any{
		"type":        "vmess",
		"tag":         shared.Tag("vmess", port),
		"listen":      "::",
		"listen_port": port,
		"users": []any{
			map[string]any{
				"uuid":    ctx.UUID,
				"alterId": 0,
			},
		},
		"proxy_protocol": false,
	}, nil
}

func ConnectionLink(ctx shared.Context, port int, name string) string {
	return shared.VMessLink(ctx.NodeIP, port, ctx.UUID, "", "", false) + "#" + name
}
