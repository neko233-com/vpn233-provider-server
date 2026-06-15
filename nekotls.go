package main

import (
	"github.com/neko233/vpn233-provider-server/internal/protocols/nekotls"
)

type NekoTLSOption = nekotls.NekoTLSOption
type NekoTLSECHOptions = nekotls.NekoTLSECHOptions
type NekoTLSRealityOptions = nekotls.NekoTLSRealityOptions

func nekotlsALPN() []string { return nekotls.ALPN() }

func nekotlsDomainMode(req normalizedRequest) bool {
	return endpointStrategy(req.NodeIP) == "domain"
}

func toNekoTLSContext(req normalizedRequest) nekotls.Context {
	return nekotls.Context{
		NodeIP:            req.NodeIP,
		ServerName:        req.ServerName,
		DataDir:           req.DataDir,
		Password:          req.Password,
		RealityServer:     req.RealityServer,
		RealityPublicKey:  req.RealityPublicKey,
		RealityShortID:    req.RealityShortID,
		NekoTLSPublicName: req.NekoTLSPublicName,
		NekoTLSECHConfig:  req.NekoTLSECHConfig,
		DomainMode:        nekotlsDomainMode(req),
	}
}

func nekotlsProxyMap(req normalizedRequest, port int, name string) map[string]any {
	return nekotls.ProxyMap(toNekoTLSContext(req), port, name)
}

func renderNekoTLSYAMLLines(m map[string]any) []string {
	return nekotls.RenderYAMLLines(m)
}

func DecodeNekoTLSOption(m map[string]any) (NekoTLSOption, error) {
	return nekotls.DecodeOption(m)
}

func singBoxNekoTLSInbound(req normalizedRequest, p ProtocolPort) (map[string]any, error) {
	return nekotls.SingBoxInbound(toNekoTLSContext(req), p.Port), nil
}

func nekotlsLink(req normalizedRequest, p ProtocolPort) string {
	return nekotls.BuildLink(toNekoTLSContext(req), p.Port, p.Name)
}

func generateNekoTLSECHConfig(publicName string) (string, error) {
	return nekotls.GenerateECHConfig(publicName)
}
