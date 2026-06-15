package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	defaultServerConfigFile = "server.yaml"
	legacyServerConfigFile  = "agent-config.json"
)

// ProxySSSGatewayConfig describes how this provider exposes itself through a
// proxysss edge gateway. The provider can generate a ready-to-run proxysss YAML
// and can self-register its HTTP route through proxysss' admin API.
type ProxySSSGatewayConfig struct {
	Enabled           bool   `json:"enabled" yaml:"enabled"`
	AdminURL          string `json:"admin_url" yaml:"admin_url"`
	BearerToken       string `json:"bearer_token" yaml:"bearer_token"`
	ProviderRouteName string `json:"provider_route_name" yaml:"provider_route_name"`
	ProviderDomain    string `json:"provider_domain" yaml:"provider_domain"`
	ProviderSubdomain string `json:"provider_subdomain" yaml:"provider_subdomain"`
	Upstream          string `json:"upstream" yaml:"upstream"`
}

// DNSAutomationConfig owns the YAML-only DNS-01/ACME settings that are emitted
// into the generated proxysss gateway plan.
type DNSAutomationConfig struct {
	Enabled        bool   `json:"enabled" yaml:"enabled"`
	Provider       string `json:"provider" yaml:"provider"`
	APIToken       string `json:"api_token" yaml:"api_token"`
	Email          string `json:"email" yaml:"email"`
	BaseDomain     string `json:"base_domain" yaml:"base_domain"`
	Production     bool   `json:"production" yaml:"production"`
	Challenge      string `json:"challenge" yaml:"challenge"`
	CreateWildcard bool   `json:"create_wildcard" yaml:"create_wildcard"`
}

func resolveServerConfigPath() string {
	if raw := strings.TrimSpace(os.Getenv("VPN233_CONFIG_PATH")); raw != "" {
		return raw
	}
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		serverPath := filepath.Join(exeDir, defaultServerConfigFile)
		if _, statErr := os.Stat(serverPath); statErr == nil {
			return serverPath
		}
		if _, statErr := os.Stat(filepath.Join(exeDir, legacyServerConfigFile)); statErr == nil {
			return serverPath
		}
	}
	if _, err := os.Stat(defaultServerConfigFile); err == nil {
		return defaultServerConfigFile
	}
	if _, err := os.Stat(legacyServerConfigFile); err == nil {
		return defaultServerConfigFile
	}
	return defaultServerConfigFile
}

func configFileCandidates() []string {
	candidates := []string{}
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		candidates = append(candidates,
			filepath.Join(exeDir, defaultServerConfigFile),
			filepath.Join(exeDir, legacyServerConfigFile),
		)
	}
	candidates = append(candidates, defaultServerConfigFile, legacyServerConfigFile)
	return candidates
}

func applyServerConfigDefaults(cfg ServerConfig) ServerConfig {
	out := normalizeRepoDefaults(cfg)
	if out.ListenAddr == "" {
		out.ListenAddr = "0.0.0.0"
	}
	if out.ListenPort <= 0 {
		out.ListenPort = 8080
	}
	if out.AdminUser == "" {
		out.AdminUser = "root"
	}
	if out.AdminPassword == "" {
		out.AdminPassword = "root"
	}
	if out.DefaultDataDir == "" {
		out.DefaultDataDir = "/etc/vpn233"
	}
	if out.DefaultPortBase <= 0 {
		out.DefaultPortBase = 10000
	}
	if out.ProxySSS.AdminURL == "" {
		out.ProxySSS.AdminURL = "http://127.0.0.1:7777"
	}
	if out.ProxySSS.ProviderRouteName == "" {
		out.ProxySSS.ProviderRouteName = "vpn233-provider-panel"
	}
	if out.ProxySSS.ProviderSubdomain == "" {
		out.ProxySSS.ProviderSubdomain = "panel"
	}
	if out.ProxySSS.Upstream == "" {
		out.ProxySSS.Upstream = "http://127.0.0.1:8080"
	}
	if out.DNSAutomation.Challenge == "" {
		out.DNSAutomation.Challenge = "dns01"
	}
	return out
}

func loadServerConfig(path string) (ServerConfig, bool, error) {
	cfg, err := loadServerConfigFile(path)
	if err == nil {
		return applyServerConfigDefaults(cfg), false, nil
	}
	if !os.IsNotExist(err) {
		return ServerConfig{}, false, err
	}
	legacyPath := filepath.Join(filepath.Dir(path), legacyServerConfigFile)
	if samePath(path, legacyPath) {
		return ServerConfig{}, false, err
	}
	legacyCfg, legacyErr := loadServerConfigFile(legacyPath)
	if legacyErr == nil {
		return applyServerConfigDefaults(legacyCfg), true, nil
	}
	return ServerConfig{}, false, err
}

func loadServerConfigFile(path string) (ServerConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ServerConfig{}, err
	}
	var cfg ServerConfig
	if shouldParseConfigAsJSON(path, raw) {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return ServerConfig{}, err
		}
		return cfg, nil
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return ServerConfig{}, err
	}
	return cfg, nil
}

func shouldParseConfigAsJSON(path string, raw []byte) bool {
	if strings.EqualFold(filepath.Ext(path), ".json") {
		return true
	}
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '{'
}

func saveServerConfig(path string, payload ServerConfig) error {
	raw, err := yaml.Marshal(applyServerConfigDefaults(payload))
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func samePath(a, b string) bool {
	cleanA, errA := filepath.Abs(a)
	cleanB, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return filepath.Clean(cleanA) == filepath.Clean(cleanB)
}

func configResponse(cfg ServerConfig, cfgPath string) map[string]any {
	cfg = applyServerConfigDefaults(cfg)
	return map[string]any{
		"node_name_default":      "vpn233-node",
		"config_path":            cfgPath,
		"config_format":          defaultServerConfigFile,
		"listen_addr":            cfg.ListenAddr,
		"listen_port":            cfg.ListenPort,
		"admin_user":             cfg.AdminUser,
		"subscribe_repo_url":     cfg.SubscribeRepoURL,
		"subscribe_repo_path":    cfg.SubscribeRepoPath,
		"subscribe_repo_branch":  cfg.SubscribeRepoBranch,
		"subscribe_verify_token": cfg.SubscribeVerifyToken,
		"default_data_dir":       cfg.DefaultDataDir,
		"default_node_ip":        cfg.DefaultNodeIP,
		"default_port_base":      cfg.DefaultPortBase,
		"default_enable_bbr":     cfg.DefaultEnableBBR,
		"default_use_mihomo":     cfg.DefaultUseMihomo,
		"default_use_singbox":    cfg.DefaultUseSingbox,
		"proxysss":               cfg.ProxySSS,
		"dns_automation":         cfg.DNSAutomation,
	}
}
