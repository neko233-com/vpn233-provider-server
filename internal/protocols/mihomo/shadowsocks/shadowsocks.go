package shadowsocks

import (
	"fmt"

	"github.com/neko233/vpn233-provider-server/internal/protocols/shared"
)

func ProxyLines(ctx shared.Context, port int, name string) ([]string, error) {
	return []string{
		fmt.Sprintf("  - name: %s", shared.YamlQuote(name)),
		"    type: ss",
		fmt.Sprintf("    server: %s", shared.YamlQuote(ctx.NodeIP)),
		fmt.Sprintf("    port: %d", port),
		"    cipher: 2022-blake3-chacha20-poly1305",
		fmt.Sprintf("    password: %s", shared.YamlQuote(ctx.Password)),
		"    udp: true",
	}, nil
}
