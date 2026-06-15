package vmess

import (
	"fmt"

	"github.com/neko233/vpn233-provider-server/internal/protocols/shared"
)

func ProxyLines(ctx shared.Context, port int, name string) ([]string, error) {
	return []string{
		fmt.Sprintf("  - name: %s", shared.YamlQuote(name)),
		"    type: vmess",
		fmt.Sprintf("    server: %s", shared.YamlQuote(ctx.NodeIP)),
		fmt.Sprintf("    port: %d", port),
		fmt.Sprintf("    uuid: %s", shared.YamlQuote(ctx.UUID)),
		"    alterId: 0",
		"    cipher: auto",
		"    udp: true",
		"    tls: false",
	}, nil
}
