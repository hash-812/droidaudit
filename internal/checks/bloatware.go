package checks

import (
	"strings"

	"github.com/hash/droidaudit/internal/rules"
)

type BloatResult struct {
	Critical int             `json:"critical"`
	Warning  int             `json:"warning"`
	Info     int             `json:"info"`
	Passed   int             `json:"passed"`
	Findings []BloatFinding  `json:"findings"`
}

type BloatFinding struct {
	Package     string `json:"package"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	SafeToRemove bool   `json:"safe_to_remove"`
	Category    string `json:"category"`
}

func CheckBloatware(a Adaptor, r *rules.Ruleset) *BloatResult {
	res := &BloatResult{}

	// Check user-installed packages
	userPkgs, _ := a.Run("shell", "cmd", "package", "list", "packages", "-3")
	// Check system packages
	sysPkgs, _ := a.Run("shell", "cmd", "package", "list", "packages", "-s")

	allPkgs := parsePackageList(userPkgs + "\n" + sysPkgs)

	for _, pkg := range allPkgs {
		if info, ok := r.Bloatware[pkg]; ok {
			finding := BloatFinding{
				Package:       pkg,
				Name:          getAppName(a, pkg),
				Severity:      info.Severity,
				Description:   info.Description,
				SafeToRemove:  info.SafeToRemove,
				Category:      info.Category,
			}

			switch info.Severity {
			case "critical":
				res.Critical++
			case "warning":
				res.Warning++
			case "info":
				res.Info++
			}

			res.Findings = append(res.Findings, finding)
		}
	}

	// Check for duplicate functionality apps
	dupes := findDuplicates(a, allPkgs, r)
	res.Findings = append(res.Findings, dupes...)

	return res
}

func parsePackageList(output string) []string {
	var pkgs []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package:") {
			pkgs = append(pkgs, strings.TrimPrefix(line, "package:"))
		}
	}
	return pkgs
}

func findDuplicates(a Adaptor, pkgs []string, r *rules.Ruleset) []BloatFinding {
	var findings []BloatFinding

	categories := map[string][]string{
		"browser":       {"chrome", "firefox", "brave", "opera", "edge", "samsung.browser", "miui.browser"},
		"keyboard":      {"gboard", "swiftkey", "fleksy", "anysoft", "openboard", "samsung.ime"},
		"launcher":      {"lawnchair", "nova", "niagara", "kvaesitso", "pixel.launcher", "samsung.launcher"},
		"file_manager":  {"files", "totalcmd", "solid", "fx", "miui.filemanager", "samsung.myfiles"},
		"gallery":       {"photos", "gallery", "google.photos", "samsung.gallery", "miui.gallery"},
		"music":         {"music", "spotify", "youtube.music", "samsung.music", "miui.music"},
		"calendar":      {"calendar", "google.calendar", "samsung.calendar", "miui.calendar"},
		"email":         {"gmail", "outlook", "k9", "fairmail", "samsung.email", "miui.email"},
	}

	for cat, known := range categories {
		var found []string
		for _, pkg := range pkgs {
			for _, k := range known {
				if strings.Contains(strings.ToLower(pkg), k) {
					found = append(found, pkg)
					break
				}
			}
		}
		if len(found) > 1 {
			for _, pkg := range found[1:] { // Keep first, flag rest
				findings = append(findings, BloatFinding{
					Package:       pkg,
					Name:          getAppName(a, pkg),
					Severity:      "info",
					Description:   "Duplicate " + cat + " app (already have " + found[0] + ")",
					SafeToRemove:  true,
					Category:      "duplicate",
				})
			}
		}
	}

	return findings
}