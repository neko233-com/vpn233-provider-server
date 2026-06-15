package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

func newFeatureState() *AppState {
	return &AppState{cfg: defaultConfig(), tokenUntil: make(map[string]time.Time)}
}

// richFeatureRequest enables every node feature for assertion coverage.
func richFeatureRequest() InstallRequest {
	return InstallRequest{
		NodeName:          "feature-node",
		NodeIP:            "edge.example.com",
		UseSingbox:        boolPtr(true),
		UseMihomo:         boolPtr(true),
		EnableBBR:         boolPtr(true),
		EnableTCPFastOpen: boolPtr(true),
		EnableMPTCP:       boolPtr(true),
		EnableHardening:   boolPtr(true),
		EnableFail2ban:    boolPtr(true),
		EnableLogRotate:   boolPtr(true),
		EnableWatchdog:    boolPtr(true),
		EnableACME:        boolPtr(true),
		ACMEDomain:        "edge.example.com",
		ACMEEmail:         "ops@example.com",
		TCPCongestion:     "bbr",
		ConnLimit:         524288,
		SelectedProtocols: []string{"singbox-nekotls", "mihomo-nekotls", "singbox-wireguard", "singbox-hysteria2"},
	}
}

// Task: performance tuning functions are emitted into the installer.
func TestShellContainsPerformanceTuning(t *testing.T) {
	res, err := newFeatureState().generateArtifacts(richFeatureRequest())
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	for _, needle := range []string{
		"tune_performance() {",
		"apply_resource_limits() {",
		"net.ipv4.tcp_congestion_control=${cc}",
		"net.core.rmem_max=134217728",
		"net.ipv4.tcp_fastopen=${tfo}",
		"net.mptcp.enabled=1",
		"DefaultLimitNOFILE=${limit}",
		"fs.file-max=2097152",
		"TCP_CONGESTION=\"bbr\"",
		"CONN_LIMIT=\"524288\"",
	} {
		if !strings.Contains(res.Shell, needle) {
			t.Fatalf("shell missing performance directive %q", needle)
		}
	}
}

// Task: security hardening + fail2ban + logrotate + watchdog emitted.
func TestShellContainsSecurityAndObservability(t *testing.T) {
	res, err := newFeatureState().generateArtifacts(richFeatureRequest())
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	for _, needle := range []string{
		"apply_security_hardening() {",
		"net.ipv4.tcp_syncookies=1",
		"install_fail2ban() {",
		"/etc/fail2ban/jail.d/vpn233.conf",
		"install_logrotate() {",
		"/etc/logrotate.d/vpn233",
		"install_watchdog() {",
		"vpn233-watchdog.timer",
	} {
		if !strings.Contains(res.Shell, needle) {
			t.Fatalf("shell missing security/observability directive %q", needle)
		}
	}
}

// Task: ACME issuance wired with domain + email.
func TestShellContainsACMEWhenEnabled(t *testing.T) {
	res, err := newFeatureState().generateArtifacts(richFeatureRequest())
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	for _, needle := range []string{
		"ENABLE_ACME=\"true\"",
		"ACME_DOMAIN=\"edge.example.com\"",
		"ACME_EMAIL=\"ops@example.com\"",
		"issue_acme_cert() {",
		"acme.sh",
		"--install-cert",
	} {
		if !strings.Contains(res.Shell, needle) {
			t.Fatalf("shell missing ACME directive %q", needle)
		}
	}
}

// Task: systemd units are hardened with resource limits + capabilities.
func TestShellSystemdUnitsHardened(t *testing.T) {
	res, err := newFeatureState().generateArtifacts(richFeatureRequest())
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	for _, needle := range []string{
		"LimitNOFILE=$CONN_LIMIT",
		"LimitNPROC=$CONN_LIMIT",
		"AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE",
	} {
		if !strings.Contains(res.Shell, needle) {
			t.Fatalf("shell missing systemd hardening %q", needle)
		}
	}
}

// Task: the node management CLI exposes the full operations surface.
func TestShellManagementCLISubcommands(t *testing.T) {
	res, err := newFeatureState().generateArtifacts(richFeatureRequest())
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	for _, sub := range []string{
		"  stats)", "  top)", "  doctor)", "  speedtest)", "  version)",
		"  backup)", "  restore)", "  cert-renew)", "  update)", "  uninstall)",
	} {
		if !strings.Contains(res.Shell, sub) {
			t.Fatalf("management CLI missing subcommand %q", sub)
		}
	}
	for _, usage := range []string{"vpn233-node speedtest", "vpn233-node uninstall", "vpn233-node update"} {
		if !strings.Contains(res.Shell, usage) {
			t.Fatalf("management CLI usage missing %q", usage)
		}
	}
}

// Task: toggles flip the emitted env vars off.
func TestShellTogglesDisableFeatures(t *testing.T) {
	req := richFeatureRequest()
	req.EnableHardening = boolPtr(false)
	req.EnableFail2ban = boolPtr(false)
	req.EnableWatchdog = boolPtr(false)
	req.EnableLogRotate = boolPtr(false)
	req.EnableTCPFastOpen = boolPtr(false)
	req.EnableMPTCP = boolPtr(false)
	res, err := newFeatureState().generateArtifacts(req)
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	for _, needle := range []string{
		"ENABLE_HARDENING=\"false\"",
		"ENABLE_FAIL2BAN=\"false\"",
		"ENABLE_WATCHDOG=\"false\"",
		"ENABLE_LOGROTATE=\"false\"",
		"ENABLE_TCP_FASTOPEN=\"false\"",
		"ENABLE_MPTCP=\"false\"",
	} {
		if !strings.Contains(res.Shell, needle) {
			t.Fatalf("expected disabled toggle %q", needle)
		}
	}
}

// Task: a custom congestion control + connection limit propagate.
func TestShellCustomCongestionAndConnLimit(t *testing.T) {
	req := richFeatureRequest()
	req.TCPCongestion = "cubic"
	req.ConnLimit = 99999
	res, err := newFeatureState().generateArtifacts(req)
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	if !strings.Contains(res.Shell, "TCP_CONGESTION=\"cubic\"") {
		t.Fatalf("expected custom congestion control")
	}
	if !strings.Contains(res.Shell, "CONN_LIMIT=\"99999\"") {
		t.Fatalf("expected custom connection limit")
	}
}

// Task: ACME defaults off for IP nodes (no domain).
func TestShellACMEDefaultOffForIPNode(t *testing.T) {
	res, err := newFeatureState().generateArtifacts(InstallRequest{
		NodeIP:            "203.0.113.10",
		SelectedProtocols: []string{"singbox-nekotls"},
	})
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	if !strings.Contains(res.Shell, "ENABLE_ACME=\"false\"") {
		t.Fatalf("ACME should default off for IP nodes")
	}
}

// Task: PowerShell installer carries performance + hardening parity.
func TestPowerShellPerformanceParity(t *testing.T) {
	res, err := newFeatureState().generateArtifacts(richFeatureRequest())
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}
	for _, needle := range []string{
		"function Optimize-Performance",
		"autotuninglevel=normal",
		"fastopen=enabled",
		"function Protect-Host",
		"$CONN_LIMIT = 524288",
	} {
		if !strings.Contains(res.PS1, needle) {
			t.Fatalf("ps1 missing %q", needle)
		}
	}
}

// Task: query + CLI parsing accept the new toggles end to end.
func TestParseInstallRequestParsesNewToggles(t *testing.T) {
	state := newFeatureState()
	var out strings.Builder
	err := runCLI(state, &out, []string{
		"generate", "--format=sh", "--node-name=cli-node", "--node-ip=panel.example.com",
		"--enable-acme=true", "--acme-domain=panel.example.com", "--acme-email=a@b.com",
		"--tcp-congestion=bbr", "--conn-limit=262144", "--enable-fail2ban=false",
		"--protocols=singbox-nekotls",
	})
	if err != nil {
		t.Fatalf("runCLI generate failed: %v", err)
	}
	shell := out.String()
	if !strings.Contains(shell, "ACME_DOMAIN=\"panel.example.com\"") {
		t.Fatalf("CLI did not propagate acme domain")
	}
	if !strings.Contains(shell, "CONN_LIMIT=\"262144\"") {
		t.Fatalf("CLI did not propagate conn limit")
	}
	if !strings.Contains(shell, "ENABLE_FAIL2BAN=\"false\"") {
		t.Fatalf("CLI did not propagate fail2ban=false")
	}
}

// Strong validation: the generated installer is syntactically valid bash.
// Skips when no usable bash is available (keeps the suite portable).
func TestGeneratedShellIsValidBash(t *testing.T) {
	bashPath := findBashForTest()
	if bashPath == "" {
		t.Skip("bash not available; skipping syntax validation")
	}
	res, err := newFeatureState().generateArtifacts(richFeatureRequest())
	if err != nil {
		t.Fatalf("generate failed: %v", err)
	}

	dir := t.TempDir()
	outer := filepath.Join(dir, "install.sh")
	if err := os.WriteFile(outer, []byte(res.Shell), 0o644); err != nil {
		t.Fatalf("write outer script: %v", err)
	}
	if out, err := exec.Command(bashPath, "-n", outer).CombinedOutput(); err != nil {
		t.Fatalf("outer installer failed bash -n: %v\n%s", err, out)
	}

	inner := extractNodeCLIScript(res.Shell)
	if inner == "" {
		t.Fatalf("could not extract vpn233-node CLI from generated shell")
	}
	innerPath := filepath.Join(dir, "vpn233-node.sh")
	if err := os.WriteFile(innerPath, []byte(inner), 0o644); err != nil {
		t.Fatalf("write inner script: %v", err)
	}
	if out, err := exec.Command(bashPath, "-n", innerPath).CombinedOutput(); err != nil {
		t.Fatalf("inner vpn233-node failed bash -n: %v\n%s", err, out)
	}
}

var heredocEscape = regexp.MustCompile("\\\\([$`\\\\])")

// extractNodeCLIScript pulls the vpn233-node heredoc body and reverses the
// unquoted-heredoc escaping so it can be syntax-checked in isolation.
func extractNodeCLIScript(shell string) string {
	const marker = "cat >/usr/local/bin/vpn233-node <<EOF"
	idx := strings.Index(shell, marker)
	if idx < 0 {
		return ""
	}
	rest := shell[idx+len(marker):]
	lines := strings.Split(rest, "\n")
	body := make([]string, 0, len(lines))
	for _, line := range lines[1:] {
		if line == "EOF" {
			break
		}
		body = append(body, heredocEscape.ReplaceAllString(line, "$1"))
	}
	return strings.Join(body, "\n")
}

func findBashForTest() string {
	if runtime.GOOS == "windows" {
		for _, p := range []string{
			`C:\Program Files\Git\bin\bash.exe`,
			`C:\Program Files\Git\usr\bin\bash.exe`,
			filepath.Join(os.Getenv("LOCALAPPDATA"), `Programs\Git\bin\bash.exe`),
		} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		return ""
	}
	if p, err := exec.LookPath("bash"); err == nil {
		return p
	}
	return ""
}
