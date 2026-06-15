package http

import (
	"github.com/neko233/vpn233-provider-server/internal/protocols/shared"
	"strconv"
)

func Inbound(ctx shared.Context, port int) (map[string]any, error) {
	return map[string]any{
		"type":        "http",
		"tag":         shared.Tag("http", port),
		"listen":      "::",
		"listen_port": port,
		"users": []any{
			map[string]any{"username": "vpn233", "password": ctx.Password},
		},
	}, nil
}

func ConnectionLink(ctx shared.Context, port int, name string) string {
	return "http://vpn233:" + ctx.Password + "@" + ctx.NodeIP + ":" + strconv.Itoa(port) + "#" + name
}
