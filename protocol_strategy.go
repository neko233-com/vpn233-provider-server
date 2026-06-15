package main

import (
	"github.com/neko233/vpn233-provider-server/internal/protocols/shared"

	sbAnyTls "github.com/neko233/vpn233-provider-server/internal/protocols/singbox/anytls"
	sbHysteria2 "github.com/neko233/vpn233-provider-server/internal/protocols/singbox/hysteria2"
	sbHttp "github.com/neko233/vpn233-provider-server/internal/protocols/singbox/http"
	sbShadowsocks "github.com/neko233/vpn233-provider-server/internal/protocols/singbox/shadowsocks"
	sbSocks "github.com/neko233/vpn233-provider-server/internal/protocols/singbox/socks"
	sbTuic "github.com/neko233/vpn233-provider-server/internal/protocols/singbox/tuic"
	sbTrojan "github.com/neko233/vpn233-provider-server/internal/protocols/singbox/trojan"
	sbTrojanGrpc "github.com/neko233/vpn233-provider-server/internal/protocols/singbox/trojan_grpc"
	sbVmess "github.com/neko233/vpn233-provider-server/internal/protocols/singbox/vmess"
	sbVmessWs "github.com/neko233/vpn233-provider-server/internal/protocols/singbox/vmess_ws"
	sbVless "github.com/neko233/vpn233-provider-server/internal/protocols/singbox/vless"
	sbVlessGrpc "github.com/neko233/vpn233-provider-server/internal/protocols/singbox/vless_grpc"
	sbVlessReality "github.com/neko233/vpn233-provider-server/internal/protocols/singbox/vless_reality"
	sbVlessRealityGrpc "github.com/neko233/vpn233-provider-server/internal/protocols/singbox/vless_reality_grpc"
	sbWireguard "github.com/neko233/vpn233-provider-server/internal/protocols/singbox/wireguard"

	mihomoAnyTls "github.com/neko233/vpn233-provider-server/internal/protocols/mihomo/anytls"
	mihomoHysteria2 "github.com/neko233/vpn233-provider-server/internal/protocols/mihomo/hysteria2"
	mihomoShadowsocks "github.com/neko233/vpn233-provider-server/internal/protocols/mihomo/shadowsocks"
	mihomoTuic "github.com/neko233/vpn233-provider-server/internal/protocols/mihomo/tuic"
	mihomoTrojan "github.com/neko233/vpn233-provider-server/internal/protocols/mihomo/trojan"
	mihomoTrojanGrpc "github.com/neko233/vpn233-provider-server/internal/protocols/mihomo/trojan_grpc"
	mihomoVless "github.com/neko233/vpn233-provider-server/internal/protocols/mihomo/vless"
	mihomoVlessGrpc "github.com/neko233/vpn233-provider-server/internal/protocols/mihomo/vless_grpc"
	mihomoVlessRealityGrpc "github.com/neko233/vpn233-provider-server/internal/protocols/mihomo/vless_reality_grpc"
	mihomoVmess "github.com/neko233/vpn233-provider-server/internal/protocols/mihomo/vmess"
	mihomoVmessWs "github.com/neko233/vpn233-provider-server/internal/protocols/mihomo/vmess_ws"
	mihomoWireguard "github.com/neko233/vpn233-provider-server/internal/protocols/mihomo/wireguard"
)

type protocolStrategy struct {
	singboxInbound    func(normalizedRequest, ProtocolPort) (map[string]any, error)
	mihomoProxyLines  func(normalizedRequest, ProtocolPort, string) ([]string, error)
	connectionLink    func(normalizedRequest, ProtocolPort) string
}

var protocolStrategies = map[string]protocolStrategy{
	"singbox-vless": {
		singboxInbound: func(req normalizedRequest, p ProtocolPort) (map[string]any, error) {
			ctx := protocolContext(req)
			return sbVless.Inbound(ctx, p.Port)
		},
		connectionLink: func(req normalizedRequest, p ProtocolPort) string {
			ctx := protocolContext(req)
			return sbVless.ConnectionLink(ctx, p.Port, p.Name)
		},
	},
	"singbox-vless-grpc": {
		singboxInbound: func(req normalizedRequest, p ProtocolPort) (map[string]any, error) {
			ctx := protocolContext(req)
			return sbVlessGrpc.Inbound(ctx, p.Port)
		},
		connectionLink: func(req normalizedRequest, p ProtocolPort) string {
			ctx := protocolContext(req)
			return sbVlessGrpc.ConnectionLink(ctx, p.Port, p.Name)
		},
	},
	"singbox-vless-reality": {
		singboxInbound: func(req normalizedRequest, p ProtocolPort) (map[string]any, error) {
			ctx := protocolContext(req)
			return sbVlessReality.Inbound(ctx, p.Port)
		},
		connectionLink: func(req normalizedRequest, p ProtocolPort) string {
			ctx := protocolContext(req)
			return sbVlessReality.ConnectionLink(ctx, p.Port, p.Name)
		},
	},
	"singbox-vless-reality-grpc": {
		singboxInbound: func(req normalizedRequest, p ProtocolPort) (map[string]any, error) {
			ctx := protocolContext(req)
			return sbVlessRealityGrpc.Inbound(ctx, p.Port)
		},
		connectionLink: func(req normalizedRequest, p ProtocolPort) string {
			ctx := protocolContext(req)
			return sbVlessRealityGrpc.ConnectionLink(ctx, p.Port, p.Name)
		},
	},
	"singbox-nekotls": {
		singboxInbound: singBoxNekoTLSInbound,
		connectionLink: func(req normalizedRequest, p ProtocolPort) string {
			return nekotlsLink(req, p)
		},
	},
	"singbox-anytls": {
		singboxInbound: func(req normalizedRequest, p ProtocolPort) (map[string]any, error) {
			ctx := protocolContext(req)
			return sbAnyTls.Inbound(ctx, p.Port)
		},
		connectionLink: func(req normalizedRequest, p ProtocolPort) string {
			ctx := protocolContext(req)
			return sbAnyTls.ConnectionLink(ctx, p.Port, p.Name)
		},
	},
	"singbox-vmess": {
		singboxInbound: func(req normalizedRequest, p ProtocolPort) (map[string]any, error) {
			ctx := protocolContext(req)
			return sbVmess.Inbound(ctx, p.Port)
		},
		connectionLink: func(req normalizedRequest, p ProtocolPort) string {
			ctx := protocolContext(req)
			return sbVmess.ConnectionLink(ctx, p.Port, p.Name)
		},
	},
	"singbox-vmess-ws": {
		singboxInbound: func(req normalizedRequest, p ProtocolPort) (map[string]any, error) {
			ctx := protocolContext(req)
			return sbVmessWs.Inbound(ctx, p.Port)
		},
		connectionLink: func(req normalizedRequest, p ProtocolPort) string {
			ctx := protocolContext(req)
			return sbVmessWs.ConnectionLink(ctx, p.Port, p.Name)
		},
	},
	"singbox-trojan": {
		singboxInbound: func(req normalizedRequest, p ProtocolPort) (map[string]any, error) {
			ctx := protocolContext(req)
			return sbTrojan.Inbound(ctx, p.Port)
		},
		connectionLink: func(req normalizedRequest, p ProtocolPort) string {
			ctx := protocolContext(req)
			return sbTrojan.ConnectionLink(ctx, p.Port, p.Name)
		},
	},
	"singbox-trojan-grpc": {
		singboxInbound: func(req normalizedRequest, p ProtocolPort) (map[string]any, error) {
			ctx := protocolContext(req)
			return sbTrojanGrpc.Inbound(ctx, p.Port)
		},
		connectionLink: func(req normalizedRequest, p ProtocolPort) string {
			ctx := protocolContext(req)
			return sbTrojanGrpc.ConnectionLink(ctx, p.Port, p.Name)
		},
	},
	"singbox-shadowsocks": {
		singboxInbound: func(req normalizedRequest, p ProtocolPort) (map[string]any, error) {
			ctx := protocolContext(req)
			return sbShadowsocks.Inbound(ctx, p.Port)
		},
		connectionLink: func(req normalizedRequest, p ProtocolPort) string {
			ctx := protocolContext(req)
			return sbShadowsocks.ConnectionLink(ctx, p.Port, p.Name)
		},
	},
	"singbox-hysteria2": {
		singboxInbound: func(req normalizedRequest, p ProtocolPort) (map[string]any, error) {
			ctx := protocolContext(req)
			return sbHysteria2.Inbound(ctx, p.Port)
		},
		connectionLink: func(req normalizedRequest, p ProtocolPort) string {
			ctx := protocolContext(req)
			return sbHysteria2.ConnectionLink(ctx, p.Port, p.Name)
		},
	},
	"singbox-tuic": {
		singboxInbound: func(req normalizedRequest, p ProtocolPort) (map[string]any, error) {
			ctx := protocolContext(req)
			return sbTuic.Inbound(ctx, p.Port)
		},
		connectionLink: func(req normalizedRequest, p ProtocolPort) string {
			ctx := protocolContext(req)
			return sbTuic.ConnectionLink(ctx, p.Port, p.Name)
		},
	},
	"singbox-wireguard": {
		singboxInbound: func(req normalizedRequest, p ProtocolPort) (map[string]any, error) {
			ctx := protocolContext(req)
			return sbWireguard.Inbound(ctx, p.Port)
		},
		connectionLink: func(req normalizedRequest, p ProtocolPort) string {
			ctx := protocolContext(req)
			return sbWireguard.ConnectionLink(ctx, p.Port, p.Name)
		},
	},
	"singbox-socks": {
		singboxInbound: func(req normalizedRequest, p ProtocolPort) (map[string]any, error) {
			ctx := protocolContext(req)
			return sbSocks.Inbound(ctx, p.Port)
		},
		connectionLink: func(req normalizedRequest, p ProtocolPort) string {
			ctx := protocolContext(req)
			return sbSocks.ConnectionLink(ctx, p.Port, p.Name)
		},
	},
	"singbox-http": {
		singboxInbound: func(req normalizedRequest, p ProtocolPort) (map[string]any, error) {
			ctx := protocolContext(req)
			return sbHttp.Inbound(ctx, p.Port)
		},
		connectionLink: func(req normalizedRequest, p ProtocolPort) string {
			ctx := protocolContext(req)
			return sbHttp.ConnectionLink(ctx, p.Port, p.Name)
		},
	},

	"mihomo-vless": {
		mihomoProxyLines: func(req normalizedRequest, p ProtocolPort, name string) ([]string, error) {
			ctx := protocolContext(req)
			return mihomoVless.ProxyLines(ctx, p.Port, name)
		},
	},
	"mihomo-vless-grpc": {
		mihomoProxyLines: func(req normalizedRequest, p ProtocolPort, name string) ([]string, error) {
			ctx := protocolContext(req)
			return mihomoVlessGrpc.ProxyLines(ctx, p.Port, name)
		},
	},
	"mihomo-vless-reality-grpc": {
		mihomoProxyLines: func(req normalizedRequest, p ProtocolPort, name string) ([]string, error) {
			ctx := protocolContext(req)
			return mihomoVlessRealityGrpc.ProxyLines(ctx, p.Port, name)
		},
	},
	"mihomo-nekotls": {
		mihomoProxyLines: func(req normalizedRequest, p ProtocolPort, name string) ([]string, error) {
			return renderNekoTLSYAMLLines(nekotlsProxyMap(req, p.Port, name)), nil
		},
	},
	"mihomo-anytls": {
		mihomoProxyLines: func(req normalizedRequest, p ProtocolPort, name string) ([]string, error) {
			ctx := protocolContext(req)
			return mihomoAnyTls.ProxyLines(ctx, p.Port, name)
		},
	},
	"mihomo-vmess": {
		mihomoProxyLines: func(req normalizedRequest, p ProtocolPort, name string) ([]string, error) {
			ctx := protocolContext(req)
			return mihomoVmess.ProxyLines(ctx, p.Port, name)
		},
	},
	"mihomo-vmess-ws": {
		mihomoProxyLines: func(req normalizedRequest, p ProtocolPort, name string) ([]string, error) {
			ctx := protocolContext(req)
			return mihomoVmessWs.ProxyLines(ctx, p.Port, name)
		},
	},
	"mihomo-trojan": {
		mihomoProxyLines: func(req normalizedRequest, p ProtocolPort, name string) ([]string, error) {
			ctx := protocolContext(req)
			return mihomoTrojan.ProxyLines(ctx, p.Port, name)
		},
	},
	"mihomo-trojan-grpc": {
		mihomoProxyLines: func(req normalizedRequest, p ProtocolPort, name string) ([]string, error) {
			ctx := protocolContext(req)
			return mihomoTrojanGrpc.ProxyLines(ctx, p.Port, name)
		},
	},
	"mihomo-shadowsocks": {
		mihomoProxyLines: func(req normalizedRequest, p ProtocolPort, name string) ([]string, error) {
			ctx := protocolContext(req)
			return mihomoShadowsocks.ProxyLines(ctx, p.Port, name)
		},
	},
	"mihomo-hysteria2": {
		mihomoProxyLines: func(req normalizedRequest, p ProtocolPort, name string) ([]string, error) {
			ctx := protocolContext(req)
			return mihomoHysteria2.ProxyLines(ctx, p.Port, name)
		},
	},
	"mihomo-tuic": {
		mihomoProxyLines: func(req normalizedRequest, p ProtocolPort, name string) ([]string, error) {
			ctx := protocolContext(req)
			return mihomoTuic.ProxyLines(ctx, p.Port, name)
		},
	},
	"mihomo-wireguard": {
		mihomoProxyLines: func(req normalizedRequest, p ProtocolPort, name string) ([]string, error) {
			ctx := protocolContext(req)
			return mihomoWireguard.ProxyLines(ctx, p.Port, name)
		},
	},
}

func protocolContext(req normalizedRequest) shared.Context {
	return shared.Context{
		NodeIP:                    req.NodeIP,
		ServerName:                req.ServerName,
		DataDir:                   req.DataDir,
		Password:                  req.Password,
		UUID:                      req.UUID,
		GRPCServiceName:           req.GRPCServiceName,
		RealityPrivateKey:         req.RealityPrivateKey,
		RealityPublicKey:          req.RealityPublicKey,
		RealityShortID:            req.RealityShortID,
		RealityServer:             req.RealityServer,
		WireGuardServerPrivateKey:  req.WireGuardServerPrivateKey,
		WireGuardServerPublicKey:   req.WireGuardServerPublicKey,
		WireGuardClientPrivateKey:  req.WireGuardClientPrivateKey,
		WireGuardClientPublicKey:   req.WireGuardClientPublicKey,
		WireGuardServerCIDR:        req.WireGuardServerCIDR,
		WireGuardClientCIDR:        req.WireGuardClientCIDR,
		NekoTLSPublicName:         req.NekoTLSPublicName,
		NekoTLSECHConfig:          req.NekoTLSECHConfig,
	}
}

func protocolStrategyForID(id string) (protocolStrategy, bool) {
	s, ok := protocolStrategies[id]
	return s, ok
}
