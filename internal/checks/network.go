package checks

import (
	"strings"

	"github.com/hash/droidaudit/internal/rules"
)

type NetResult struct {
	Critical int           `json:"critical"`
	Warning  int           `json:"warning"`
	Info     int           `json:"info"`
	Passed   int           `json:"passed"`
	Findings []NetFinding  `json:"findings"`
}

type NetFinding struct {
	Type        string `json:"type"`
	Detail      string `json:"detail"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

func CheckNetwork(a Adaptor, r *rules.Ruleset) *NetResult {
	res := &NetResult{}

	// Check open ports (netstat/ss)
	ports := checkOpenPorts(a, r)
	res.Findings = append(res.Findings, ports...)

	// Check DNS settings
	dns := checkDNS(a, r)
	res.Findings = append(res.Findings, dns...)

	// Check active connections
	conns := checkConnections(a, r)
	res.Findings = append(res.Findings, conns...)

	// Check VPN/proxy
	vpn := checkVPN(a)
	res.Findings = append(res.Findings, vpn...)

	// Count severities
	for _, f := range res.Findings {
		switch f.Severity {
		case "critical":
			res.Critical++
		case "warning":
			res.Warning++
		case "info":
			res.Info++
		default:
			res.Passed++
		}
	}

	return res
}

func checkOpenPorts(a Adaptor, r *rules.Ruleset) []NetFinding {
	var findings []NetFinding

	out, _ := a.RunRoot("ss", "-tlnp", "2>/dev/null || netstat", "-tlnp", "2>/dev/null")
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "LISTEN") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				addr := fields[3]
				findings = append(findings, NetFinding{
					Type:        "open_port",
					Detail:      addr,
					Severity:    classifyPort(addr, r),
					Description: "Listening port: " + addr,
				})
			}
		}
	}
	return findings
}

func checkDNS(a Adaptor, r *rules.Ruleset) []NetFinding {
	var findings []NetFinding

	out, _ := a.Run("shell", "getprop", "|", "grep", "dns")
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "net.dns") {
			fields := strings.Split(line, "]: [")
			if len(fields) == 2 {
				dns := strings.TrimSuffix(fields[1], "]")
				if isSuspiciousDNS(dns) {
					findings = append(findings, NetFinding{
						Type:        "dns",
						Detail:      dns,
						Severity:    "warning",
						Description: "Non-standard DNS server: " + dns,
					})
				}
			}
		}
	}
	return findings
}

func checkConnections(a Adaptor, r *rules.Ruleset) []NetFinding {
	var findings []NetFinding

	out, _ := a.RunRoot("ss", "-tnp", "2>/dev/null | grep ESTAB")
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 5 {
			remote := fields[4]
			if isSuspiciousIP(remote, r) {
				findings = append(findings, NetFinding{
					Type:        "connection",
					Detail:      remote,
					Severity:    "warning",
					Description: "Connection to suspicious IP: " + remote,
				})
			}
		}
	}
	return findings
}

func checkVPN(a Adaptor) []NetFinding {
	var findings []NetFinding

	out, _ := a.Run("shell", "ip", "link", "show", "type", "tun")
	if strings.Contains(out, "tun") {
		findings = append(findings, NetFinding{
			Type:        "vpn",
			Detail:      "active",
			Severity:    "info",
			Description: "VPN tunnel interface detected",
		})
	}
	return findings
}

func classifyPort(addr string, r *rules.Ruleset) string {
	for _, suspicious := range r.SuspiciousPorts {
		if strings.Contains(addr, suspicious) {
			return "critical"
		}
	}
	if strings.Contains(addr, ":22") || strings.Contains(addr, ":23") ||
		strings.Contains(addr, ":3389") || strings.Contains(addr, ":5900") {
		return "critical"
	}
	return "info"
}

func isSuspiciousDNS(dns string) bool {
	standard := []string{"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112"}
	for _, s := range standard {
		if dns == s {
			return false
		}
	}
	return true
}

func isSuspiciousIP(ip string, r *rules.Ruleset) bool {
	for _, net := range r.SuspiciousNetworks {
		if strings.HasPrefix(ip, net) {
			return true
		}
	}
	return false
}