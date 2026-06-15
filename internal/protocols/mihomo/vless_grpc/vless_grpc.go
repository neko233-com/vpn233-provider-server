package vless_grpc

import (
	"fmt"

	"github.com/neko233/vpn233-provider-server/internal/protocols/shared"
)

func ProxyLines(ctx shared.Context, port int, name string) ([]string, error) {
	return []string{
		fmt.Sprintf("  - name: %s", shared.YamlQuote(name)),
		"    type: vless",
		fmt.Sprintf("    server: %s", shared.YamlQuote(ctx.NodeIP)),
		fmt.Sprintf("    port: %d", port),
		fmt.Sprintf("    uuid: %s", shared.YamlQuote(ctx.UUID)),
		"    udp: true",
		"    tls: true",
		fmt.Sprintf("    servername: %s", shared.YamlQuote(ctx.ServerName)),
		"    skip-cert-verify: true",
		"    network: grpc",
		"    grpc-opts:",
		fmt.Sprintf("      grpc-service-name: %s", shared.YamlQuote(ctx.GRPCServiceName)),
	}, nil
}
