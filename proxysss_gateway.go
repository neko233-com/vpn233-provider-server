package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

func runCLIGatewayPlan(state *AppState, stdout io.Writer) error {
	plan, err := buildProxySSSGatewayYAML(state.snapshotConfig())
	if err != nil {
		return err
	}
	_, err = io.WriteString(stdout, plan)
	return err
}

func runCLIGatewayRegister(state *AppState, stdout io.Writer) error {
	result, err := registerProxySSSProviderRoute(http.DefaultClient, state.snapshotConfig())
	if err != nil {
		return err
	}
	return writeCLIJSON(stdout, result)
}

func providerGatewayDomain(cfg ServerConfig) (string, error) {
	cfg = applyServerConfigDefaults(cfg)
	if cfg.ProxySSS.ProviderDomain != "" {
		return cfg.ProxySSS.ProviderDomain, nil
	}
	if cfg.DNSAutomation.BaseDomain == "" {
		return "", fmt.Errorf("proxysss provider_domain or dns_automation.base_domain is required")
	}
	if cfg.ProxySSS.ProviderSubdomain == "" {
		return cfg.DNSAutomation.BaseDomain, nil
	}
	return cfg.ProxySSS.ProviderSubdomain + "." + cfg.DNSAutomation.BaseDomain, nil
}

func managedDNSDomains(cfg ServerConfig, providerDomain string) []string {
	cfg = applyServerConfigDefaults(cfg)
	if cfg.DNSAutomation.BaseDomain == "" {
		return uniqueStrings([]string{providerDomain})
	}
	domains := []string{cfg.DNSAutomation.BaseDomain}
	if cfg.DNSAutomation.CreateWildcard {
		domains = append(domains, "*."+cfg.DNSAutomation.BaseDomain)
	}
	coveredByWildcard := cfg.DNSAutomation.CreateWildcard && strings.HasSuffix(providerDomain, "."+cfg.DNSAutomation.BaseDomain)
	if providerDomain != "" && providerDomain != cfg.DNSAutomation.BaseDomain && !coveredByWildcard {
		domains = append(domains, providerDomain)
	}
	return uniqueStrings(domains)
}

func buildProxySSSGatewayYAML(cfg ServerConfig) (string, error) {
	cfg = applyServerConfigDefaults(cfg)
	if !cfg.ProxySSS.Enabled {
		return "", fmt.Errorf("proxysss.enabled is false")
	}
	if !cfg.DNSAutomation.Enabled {
		return "", fmt.Errorf("dns_automation.enabled is false")
	}
	if cfg.DNSAutomation.Provider == "" {
		return "", fmt.Errorf("dns_automation.provider is required")
	}
	if cfg.DNSAutomation.APIToken == "" {
		return "", fmt.Errorf("dns_automation.api_token is required")
	}
	if cfg.DNSAutomation.Email == "" {
		return "", fmt.Errorf("dns_automation.email is required")
	}
	providerDomain, err := providerGatewayDomain(cfg)
	if err != nil {
		return "", err
	}
	plan := map[string]any{
		"http": map[string]any{
			"plain_bind": "0.0.0.0:80",
			"tls_bind":   "0.0.0.0:443",
			"h3_bind":    "0.0.0.0:443",
			"tls": map[string]any{
				"mode":                            "acme_managed",
				"cert_path":                       "certs/proxysss-cert.pem",
				"key_path":                        "certs/proxysss-key.pem",
				"generate_self_signed_if_missing": false,
				"server_name":                     providerDomain,
				"acme": map[string]any{
					"email":                cfg.DNSAutomation.Email,
					"challenge":            cfg.DNSAutomation.Challenge,
					"domains":              managedDNSDomains(cfg, providerDomain),
					"directory_production": cfg.DNSAutomation.Production,
					"renew_interval_hours": 12,
					"dns": map[string]any{
						"provider": cfg.DNSAutomation.Provider,
						"credentials": map[string]any{
							"api_token": cfg.DNSAutomation.APIToken,
						},
					},
				},
			},
		},
		"admin": map[string]any{
			"enabled":          true,
			"bind":             "127.0.0.1:7777",
			"bearer_token":     cfg.ProxySSS.BearerToken,
			"enable_write_ops": true,
		},
		"monitoring": map[string]any{
			"enabled": true,
			"path":    "/metrics",
			"format":  "prometheus",
		},
		"runtime": map[string]any{
			"performance": map[string]any{
				"enabled":         true,
				"profile":         "latency",
				"traffic_profile": "small",
				"adaptive_system": true,
				"socket_extreme":  true,
				"log_on_start":    true,
			},
			"watchdog": map[string]any{
				"enabled":                 true,
				"restart_critical_tasks":  true,
				"restart_backoff_secs":    2,
				"heartbeat_interval_secs": 30,
			},
		},
		"services": map[string]any{
			"domain_routes": []any{
				map[string]any{
					"name":            cfg.ProxySSS.ProviderRouteName,
					"domains":         []string{providerDomain},
					"path_prefix":     "/",
					"upstream":        cfg.ProxySSS.Upstream,
					"strip_prefix":    false,
					"forward_headers": false,
				},
			},
		},
	}
	raw, err := yaml.Marshal(plan)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func buildProxySSSRouteUpsertPayload(cfg ServerConfig) (map[string]any, error) {
	cfg = applyServerConfigDefaults(cfg)
	if !cfg.ProxySSS.Enabled {
		return nil, fmt.Errorf("proxysss.enabled is false")
	}
	providerDomain, err := providerGatewayDomain(cfg)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"name":         cfg.ProxySSS.ProviderRouteName,
		"domains":      []string{providerDomain},
		"path_prefix":  "/",
		"upstream":     cfg.ProxySSS.Upstream,
		"strip_prefix": false,
	}, nil
}

func registerProxySSSProviderRoute(client *http.Client, cfg ServerConfig) (map[string]any, error) {
	cfg = applyServerConfigDefaults(cfg)
	if client == nil {
		client = http.DefaultClient
	}
	if cfg.ProxySSS.AdminURL == "" {
		return nil, fmt.Errorf("proxysss.admin_url is required")
	}
	if cfg.ProxySSS.BearerToken == "" {
		return nil, fmt.Errorf("proxysss.bearer_token is required")
	}
	payload, err := buildProxySSSRouteUpsertPayload(cfg)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	adminURL := strings.TrimRight(cfg.ProxySSS.AdminURL, "/") + "/v1/domain-routes/upsert"
	req, err := http.NewRequest(http.MethodPost, adminURL, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.ProxySSS.BearerToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("proxysss register failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	providerDomain, _ := providerGatewayDomain(cfg)
	result := map[string]any{
		"ok":         true,
		"admin_url":  adminURL,
		"domain":     providerDomain,
		"route_name": cfg.ProxySSS.ProviderRouteName,
		"upstream":   cfg.ProxySSS.Upstream,
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 {
		var parsed any
		if err := json.Unmarshal(trimmed, &parsed); err == nil {
			result["proxysss_response"] = parsed
		} else {
			result["proxysss_response"] = string(trimmed)
		}
	}
	return result, nil
}

func (a *AppState) proxySSSGatewayYAMLHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "only GET"})
		return
	}
	plan, err := buildProxySSSGatewayYAML(a.snapshotConfig())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=\"proxysss.yaml\"")
	writeText(w, http.StatusOK, plan)
}

func (a *AppState) proxySSSRegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "only POST"})
		return
	}
	result, err := registerProxySSSProviderRoute(http.DefaultClient, a.snapshotConfig())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func uniqueStrings(items []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}
