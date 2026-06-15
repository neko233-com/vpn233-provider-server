package wireguard

import (
	"github.com/neko233/vpn233-provider-server/internal/protocols/shared"
	"strconv"
)

func Inbound(ctx shared.Context, port int) (map[string]any, error) {
	return map[string]any{
		"type":        "wireguard",
		"tag":         shared.Tag("wg", port),
		"listen_port": port,
		"address":     []string{ctx.WireGuardServerCIDR},
		"private_key": ctx.WireGuardServerPrivateKey,
		"mtu":         1408,
		"peers": []any{
			map[string]any{
				"public_key":     ctx.WireGuardClientPublicKey,
				"pre_shared_key": ctx.WireGuardPresharedKey,
				"allowed_ips":    []string{ctx.WireGuardClientCIDR},
			},
		},
	}, nil
}

func ConnectionLink(ctx shared.Context, port int, name string) string {
	return "wireguard://" + ctx.WireGuardClientPrivateKey + "@" + ctx.NodeIP + ":" + strconv.Itoa(port) + "?publickey=" + ctx.WireGuardServerPublicKey + "&presharedkey=" + ctx.WireGuardPresharedKey + "&address=" + ctx.WireGuardClientCIDR + "#" + name
}
