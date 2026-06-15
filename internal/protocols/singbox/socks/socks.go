package socks

import (
	"github.com/neko233/vpn233-provider-server/internal/protocols/shared"
	"strconv"
)

func Inbound(ctx shared.Context, port int) (map[string]any, error) {
	return map[string]any{
		"type":        "socks",
		"tag":         shared.Tag("socks", port),
		"listen":      "::",
		"listen_port": port,
		"users": []any{
			map[string]any{"username": "vpn233", "password": ctx.Password},
		},
		"udp": true,
	}, nil
}

func ConnectionLink(ctx shared.Context, port int, name string) string {
	return "socks5://vpn233:" + ctx.Password + "@" + ctx.NodeIP + ":" + strconv.Itoa(port) + "#" + name
}
