package tuic

import (
	"fmt"

	"github.com/neko233/vpn233-provider-server/internal/protocols/shared"
)

func ProxyLines(ctx shared.Context, port int, name string) ([]string, error) {
	return []string{
		fmt.Sprintf("  - name: %s", shared.YamlQuote(name)),
		"    type: tuic",
		fmt.Sprintf("    server: %s", shared.YamlQuote(ctx.NodeIP)),
		fmt.Sprintf("    port: %d", port),
		fmt.Sprintf("    uuid: %s", shared.YamlQuote(ctx.UUID)),
		fmt.Sprintf("    password: %s", shared.YamlQuote(ctx.Password)),
		"    udp: true",
		fmt.Sprintf("    sni: %s", shared.YamlQuote(ctx.ServerName)),
		"    skip-cert-verify: true",
		"    congestion-controller: bbr",
	}, nil
}
