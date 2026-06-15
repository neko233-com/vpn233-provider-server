package anytls

import (
	"fmt"
	"github.com/neko233/vpn233-provider-server/internal/protocols/shared"
)

func Inbound(ctx shared.Context, port int) (map[string]any, error) {
	return map[string]any{
		"type":        "anytls",
		"tag":         shared.Tag("anytls", port),
		"listen":      "::",
		"listen_port": port,
		"users": []any{
			map[string]any{
				"name":     "vpn233",
				"password": ctx.Password,
			},
		},
		"padding_scheme": []string{},
		"tls":            shared.SingBoxTLSConfig(ctx, []string{"h2", "http/1.1"}),
	}, nil
}

func ConnectionLink(ctx shared.Context, port int, name string) string {
	return fmt.Sprintf("anytls://%s@%s:%d/?sni=%s&insecure=1#%s", ctx.Password, ctx.NodeIP, port, ctx.ServerName, name)
}
