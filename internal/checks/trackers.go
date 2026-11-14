package checks

import (
	"strings"

	"github.com/hash/droidaudit/internal/rules"
)

type TrackerResult struct {
	Critical int             `json:"critical"`
	Warning  int             `json:"warning"`
	Info     int             `json:"info"`
	Passed   int             `json:"passed"`
	Findings []TrackerFinding `json:"findings"`
}

type TrackerFinding struct {
	Package   string   `json:"package"`
	Name      string   `json:"name"`
	Trackers  []string `json:"trackers"`
	Severity  string   `json:"severity"`
	Categories []string `json:"categories"`
}

func CheckTrackers(a Adaptor, r *rules.Ruleset) *TrackerResult {
	res := &TrackerResult{}

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

		trackers, categories := detectTrackers(a, pkg, r)
		if len(trackers) == 0 {
			res.Passed++
			continue
		}

		finding := TrackerFinding{
			Package:    pkg,
			Name:       getAppName(a, pkg),
			Trackers:   trackers,
			Categories: categories,
		}

		if len(trackers) >= 5 || hasCriticalTracker(trackers, r) {
			finding.Severity = "critical"
			res.Critical++
		} else if len(trackers) >= 2 {
			finding.Severity = "warning"
			res.Warning++
		} else {
			finding.Severity = "info"
			res.Info++
		}

		res.Findings = append(res.Findings, finding)
	}

	return res
}

func detectTrackers(a Adaptor, pkg string, r *rules.Ruleset) ([]string, []string) {
	// Check installed APK path
	pathOut, _ := a.Run("shell", "cmd", "package", "path", pkg)
	path := strings.TrimPrefix(strings.TrimSpace(pathOut), "package:")

	if path == "" {
		return nil, nil
	}

	// Extract APK and scan for tracker signatures
	// In real implementation: pull APK, analyze with ClassyShark/Exodus signatures
	// For now, simulate based on package name patterns
	var trackers []string
	var categories []string

	pkgLower := strings.ToLower(pkg)
	for sig, cat := range r.Trackers {
		if strings.Contains(pkgLower, sig) {
			trackers = append(trackers, sig)
			categories = append(categories, cat)
		}
	}

	// Also check for known tracker libraries in app data
	libOut, _ := a.Run("shell", "ls", "/data/app/"+pkg+"*/lib/arm64/ 2>/dev/null || ls /data/app/"+pkg+"*/lib/arm/ 2>/dev/null")
	for _, line := range strings.Split(libOut, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "tracker") || strings.Contains(line, "analytics") ||
			strings.Contains(line, "crashlytics") || strings.Contains(line, "firebase") {
			trackers = append(trackers, line)
			categories = append(categories, "analytics")
		}
	}

	return unique(trackers), unique(categories)
}

func hasCriticalTracker(trackers []string, r *rules.Ruleset) bool {
	for _, t := range trackers {
		if r.IsCriticalTracker(t) {
			return true
		}
	}
	return false
}

func unique(slice []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}