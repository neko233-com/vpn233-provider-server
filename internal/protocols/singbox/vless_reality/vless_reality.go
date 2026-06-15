package vless_reality

import (
	"fmt"

	"github.com/neko233/vpn233-provider-server/internal/protocols/shared"
)

func Inbound(ctx shared.Context, port int) (map[string]any, error) {
	inbound := shared.SingBoxInboundVLESS(port, ctx.UUID)
	inbound["tag"] = shared.Tag("vless-reality", port)
	inbound["tls"] = shared.SingBoxRealityConfig(ctx, []string{"h2", "http/1.1"})
	return inbound, nil
}

func ConnectionLink(ctx shared.Context, port int, name string) string {
	return fmt.Sprintf("vless://%s@%s:%d?security=reality&sni=%s&pbk=%s&sid=%s&type=tcp#%s", ctx.UUID, ctx.NodeIP, port, ctx.RealityServer, ctx.RealityPublicKey, ctx.RealityShortID, name)
}
