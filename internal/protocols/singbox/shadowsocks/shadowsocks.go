package shadowsocks

import (
	"encoding/base64"
	"fmt"

	"github.com/neko233/vpn233-provider-server/internal/protocols/shared"
)

func Inbound(ctx shared.Context, port int) (map[string]any, error) {
	return map[string]any{
		"type":        "shadowsocks",
		"tag":         shared.Tag("ss", port),
		"listen":      "::",
		"listen_port": port,
		"method":      "2022-blake3-chacha20-poly1305",
		"password":    ctx.Password,
	}, nil
}

func ConnectionLink(ctx shared.Context, port int, name string) string {
	userInfo := base64.StdEncoding.EncodeToString([]byte("2022-blake3-chacha20-poly1305:" + ctx.Password))
	return fmt.Sprintf("ss://%s@%s:%d#%s", userInfo, ctx.NodeIP, port, name)
}
