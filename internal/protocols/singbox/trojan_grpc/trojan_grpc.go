package trojan_grpc

import (
	"fmt"
	"github.com/neko233/vpn233-provider-server/internal/protocols/shared"
)

func Inbound(ctx shared.Context, port int) (map[string]any, error) {
	return map[string]any{
		"type":        "trojan",
		"tag":         shared.Tag("trojan-grpc", port),
		"listen":      "::",
		"listen_port": port,
		"users": []any{
			map[string]any{
				"name":     "admin",
				"password": ctx.Password,
			},
		},
		"tls":       shared.SingBoxTLSConfig(ctx, []string{"h2", "http/1.1"}),
		"transport": shared.GRPCTransport(ctx.GRPCServiceName),
	}, nil
}

func ConnectionLink(ctx shared.Context, port int, name string) string {
	return fmt.Sprintf("trojan://%s@%s:%d?sni=%s&type=grpc&serviceName=%s#%s", ctx.Password, ctx.NodeIP, port, ctx.ServerName, ctx.GRPCServiceName, name)
}
