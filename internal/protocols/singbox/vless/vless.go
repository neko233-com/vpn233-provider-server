package vless

import (
	"fmt"

	"github.com/neko233/vpn233-provider-server/internal/protocols/shared"
)

func Inbound(ctx shared.Context, port int) (map[string]any, error) {
	in := shared.SingBoxInboundVLESS(port, ctx.UUID)
	in["tag"] = shared.Tag("vless", port)
	return in, nil
}

func ConnectionLink(ctx shared.Context, port int, name string) string {
	return fmt.Sprintf("vless://%s@%s:%d?security=none&type=tcp#%s", ctx.UUID, ctx.NodeIP, port, name)
}
