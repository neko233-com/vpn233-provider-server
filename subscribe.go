package main

import (
	"fmt"
	"net/http"
	"strings"
)

// Subscribe conversion: given node parameters, emit a ready-to-use config for a
// requested client target. The flagship target is `clash-meta-nekotls`, which
// produces a forked-mihomo config that prefers `type: nekotls` proxies.
const (
	subscribeTargetClashMetaNekoTLS = "clash-meta-nekotls"
	subscribeTargetClashMeta        = "clash-meta"
	subscribeTargetClash            = "clash"
	subscribeTargetSingBox          = "sing-box"
	subscribeTargetLinks            = "links"
)

// subscribeTargets is the advertised list of supported conversion targets.
func subscribeTargets() []string {
	return []string{
		subscribeTargetClashMetaNekoTLS,
		subscribeTargetClashMeta,
		subscribeTargetClash,
		subscribeTargetSingBox,
		subscribeTargetLinks,
	}
}

func isSupportedSubscribeTarget(target string) bool {
	for _, t := range subscribeTargets() {
		if t == target {
			return true
		}
	}
	return false
}

// ensureProtocol appends id to the selection if not already present.
func ensureProtocol(selected []string, id string) []string {
	for _, s := range selected {
		if s == id {
			return selected
		}
	}
	return append(append([]string{}, selected...), id)
}

// substituteNekoTLS rewrites NekoTLS ids to their AnyTLS equivalents so that a
// stock (non-fork) Clash/Clash.Meta core can still parse the output.
func substituteNekoTLS(selected []string) []string {
	out := make([]string, 0, len(selected))
	for _, s := range selected {
		switch s {
		case "mihomo-nekotls":
			out = append(out, "mihomo-anytls")
		case "singbox-nekotls":
			out = append(out, "singbox-anytls")
		default:
			out = append(out, s)
		}
	}
	return out
}

// buildSubscriptionArtifact normalizes the request once and renders the chosen
// subscribe target. It returns the body plus the HTTP content type.
func (a *AppState) buildSubscriptionArtifact(req InstallRequest, target string) (string, string, error) {
	switch target {
	case subscribeTargetLinks:
		res, err := a.generateArtifacts(req)
		if err != nil {
			return "", "", err
		}
		return strings.Join(res.Node.Links, "\n"), "text/plain; charset=utf-8", nil

	case subscribeTargetSingBox:
		res, err := a.generateArtifacts(req)
		if err != nil {
			return "", "", err
		}
		cfg, err := buildSingBoxConfig(res.profile, res.mapping)
		if err != nil {
			return "", "", err
		}
		return cfg, "application/json; charset=utf-8", nil

	case subscribeTargetClashMetaNekoTLS:
		req.UseMihomo = boolPtrValue(true)
		req.SelectedProtocols = ensureProtocol(req.SelectedProtocols, "mihomo-nekotls")
		res, err := a.generateArtifacts(req)
		if err != nil {
			return "", "", err
		}
		cfg, err := buildMihomoTemplate(res.profile, res.mapping)
		if err != nil {
			return "", "", err
		}
		return cfg, "text/yaml; charset=utf-8", nil

	case subscribeTargetClash, subscribeTargetClashMeta:
		req.UseMihomo = boolPtrValue(true)
		req.SelectedProtocols = substituteNekoTLS(req.SelectedProtocols)
		res, err := a.generateArtifacts(req)
		if err != nil {
			return "", "", err
		}
		cfg, err := buildMihomoTemplate(res.profile, res.mapping)
		if err != nil {
			return "", "", err
		}
		return cfg, "text/yaml; charset=utf-8", nil

	default:
		return "", "", fmt.Errorf("unsupported subscribe target: %q", target)
	}
}

func (a *AppState) subscribeConvertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "only GET"})
		return
	}
	cfg := a.snapshotConfig()
	if cfg.SubscribeVerifyToken != "" {
		if strings.TrimSpace(r.URL.Query().Get("token")) != cfg.SubscribeVerifyToken {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "subscribe token mismatch"})
			return
		}
	}
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	if target == "" {
		target = subscribeTargetClashMetaNekoTLS
	}
	if !isSupportedSubscribeTarget(target) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":   "unsupported subscribe target",
			"target":  target,
			"targets": subscribeTargets(),
		})
		return
	}
	req, err := parseInstallRequestFromQuery(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	body, contentType, err := a.buildSubscriptionArtifact(req, target)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Subscribe-Target", target)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}
