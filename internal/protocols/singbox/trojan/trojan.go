package trojan

import (
	"fmt"
	"github.com/neko233/vpn233-provider-server/internal/protocols/shared"
)

func Inbound(ctx shared.Context, port int) (map[string]any, error) {
	return map[string]any{
		"type":        "trojan",
		"tag":         shared.Tag("trojan", port),
		"listen":      "::",
		"listen_port": port,
		"users": []any{
			map[string]any{
				"name":     "admin",
				"password": ctx.Password,
			},
		},
		"tls": shared.SingBoxTLSConfig(ctx, []string{"h2", "http/1.1"}),
	}, nil
}

func ConnectionLink(ctx shared.Context, port int, name string) string {
	return fmt.Sprintf("trojan://%s@%s:%d?sni=%s#%s", ctx.Password, ctx.NodeIP, port, ctx.ServerName, name)
}
