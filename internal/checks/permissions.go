package checks

import (
	"strings"

	"github.com/hash/droidaudit/internal/rules"
)

type PermResult struct {
	Critical int                `json:"critical"`
	Warning  int                `json:"warning"`
	Info     int                `json:"info"`
	Passed   int                `json:"passed"`
	Findings []PermFinding      `json:"findings"`
}

type PermFinding struct {
	Package     string   `json:"package"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
}

func CheckPermissions(a Adaptor, r *rules.Ruleset) *PermResult {
	res := &PermResult{}

	pkgs, err := a.Run("shell", "cmd", "package", "list", "packages", "-3")
	if err != nil {
		return res
	}

	for _, line := range strings.Split(pkgs, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "package:") {
			continue
		}
		pkg := strings.TrimPrefix(line, "package:")

		perms, _ := a.Run("shell", "cmd", "package", "info", pkg)
		dangerous := extractDangerousPerms(perms, r)

		if len(dangerous) == 0 {
			res.Passed++
			continue
		}

		finding := PermFinding{
			Package:     pkg,
			Name:        getAppName(a, pkg),
			Permissions: dangerous,
		}

		finding.Severity, finding.Description = classifyPermissions(dangerous, r)
		res.Findings = append(res.Findings, finding)

		switch finding.Severity {
		case "critical":
			res.Critical++
		case "warning":
			res.Warning++
		case "info":
			res.Info++
		}
	}

	return res
}

func extractDangerousPerms(output string, r *rules.Ruleset) []string {
	var perms []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "android.permission.") {
			perm := strings.Split(line, ":")[0]
			if r.IsDangerous(perm) || r.IsSuspicious(perm) {
				perms = append(perms, perm)
			}
		}
	}
	return perms
}

func getAppName(a Adaptor, pkg string) string {
	_, _ = a.Run("shell", "cmd", "package", "info", pkg, "|", "grep", "-m1", "label:")
	// Simplified - real implementation would parse properly
	return pkg
}

func classifyPermissions(perms []string, r *rules.Ruleset) (string, string) {
	hasCritical := false
	hasWarning := false
	descriptions := []string{}

	for _, p := range perms {
		if r.IsCritical(p) {
			hasCritical = true
			descriptions = append(descriptions, r.GetDescription(p))
		} else if r.IsWarning(p) {
			hasWarning = true
			descriptions = append(descriptions, r.GetDescription(p))
		}
	}

	if hasCritical {
		return "critical", strings.Join(descriptions, "; ")
	}
	if hasWarning {
		return "warning", strings.Join(descriptions, "; ")
	}
	return "info", strings.Join(descriptions, "; ")
}

type Adaptor interface {
	Run(cmd ...string) (string, error)
	RunRoot(cmd ...string) (string, error)
	HasRoot() bool
}