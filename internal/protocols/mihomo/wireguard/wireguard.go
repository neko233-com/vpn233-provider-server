package wireguard

import (
	"fmt"

	"github.com/neko233/vpn233-provider-server/internal/protocols/shared"
)

func ProxyLines(ctx shared.Context, port int, name string) ([]string, error) {
	return []string{
		fmt.Sprintf("  - name: %s", shared.YamlQuote(name)),
		"    type: wireguard",
		fmt.Sprintf("    server: %s", shared.YamlQuote(ctx.NodeIP)),
		fmt.Sprintf("    port: %d", port),
		fmt.Sprintf("    ip: %s", shared.YamlQuote(ctx.WireGuardClientCIDR)),
		fmt.Sprintf("    private-key: %s", shared.YamlQuote(ctx.WireGuardClientPrivateKey)),
		fmt.Sprintf("    public-key: %s", shared.YamlQuote(ctx.WireGuardServerPublicKey)),
		fmt.Sprintf("    pre-shared-key: %s", shared.YamlQuote(ctx.WireGuardPresharedKey)),
		"    udp: true",
		"    mtu: 1408",
	}, nil
}
