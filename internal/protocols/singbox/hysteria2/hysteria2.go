package hysteria2

import (
	"fmt"
	"github.com/neko233/vpn233-provider-server/internal/protocols/shared"
)

func Inbound(ctx shared.Context, port int) (map[string]any, error) {
	return map[string]any{
		"type":        "hysteria2",
		"tag":         shared.Tag("hysteria2", port),
		"listen":      "::",
		"listen_port": port,
		"up_mbps":     100,
		"down_mbps":   1000,
		"users": []any{
			map[string]any{"password": ctx.Password},
		},
		"tls": shared.SingBoxTLSConfig(ctx, []string{"h3"}),
	}, nil
}

func ConnectionLink(ctx shared.Context, port int, name string) string {
	return fmt.Sprintf("hysteria2://%s@%s:%d?sni=%s&insecure=1#%s", ctx.Password, ctx.NodeIP, port, ctx.ServerName, name)
}
