package vless_grpc

import (
	"fmt"

	"github.com/neko233/vpn233-provider-server/internal/protocols/shared"
)

func Inbound(ctx shared.Context, port int) (map[string]any, error) {
	inbound := shared.SingBoxInboundVLESS(port, ctx.UUID)
	inbound["tag"] = shared.Tag("vless-grpc", port)
	inbound["tls"] = shared.SingBoxTLSConfig(ctx, []string{"h2", "http/1.1"})
	inbound["transport"] = shared.GRPCTransport(ctx.GRPCServiceName)
	return inbound, nil
}

func ConnectionLink(ctx shared.Context, port int, name string) string {
	return fmt.Sprintf("vless://%s@%s:%d?security=tls&sni=%s&type=grpc&serviceName=%s#%s", ctx.UUID, ctx.NodeIP, port, ctx.ServerName, ctx.GRPCServiceName, name)
}
