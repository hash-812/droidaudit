package report

import (
	"encoding/json"
	"fmt"
	"io"
	"text/template"

	"github.com/hash/droidaudit/internal/scan"
)

func WriteJSON(result *scan.Result, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func WriteText(result *scan.Result, w io.Writer) error {
	fmt.Fprintf(w, "=== droidaudit Report ===\n")
	fmt.Fprintf(w, "Device: %s (%s)\n", result.Device.Model, result.Device.Serial)
	fmt.Fprintf(w, "Android: %s (SDK %s)\n", result.Device.AndroidVer, result.Device.SDK)
	fmt.Fprintf(w, "Kernel: %s\n", result.Device.Kernel)
	fmt.Fprintf(w, "Rooted: %v\n", result.Device.Rooted)
	fmt.Fprintf(w, "Scan Time: %s\n\n", result.Timestamp)

	fmt.Fprintf(w, "SUMMARY:\n")
	fmt.Fprintf(w, "  Critical: %d\n", result.Summary.Critical)
	fmt.Fprintf(w, "  Warning:  %d\n", result.Summary.Warning)
	fmt.Fprintf(w, "  Info:     %d\n", result.Summary.Info)
	fmt.Fprintf(w, "  Passed:   %d\n\n", result.Summary.Passed)

	printSection(w, "PERMISSIONS", result.Permissions)
	printSection(w, "TRACKERS", result.Trackers)
	printSection(w, "NETWORK", result.Network)
	printSection(w, "BLOATWARE", result.Bloatware)
	printSection(w, "SETTINGS", result.Settings)

	return nil
}

func printSection(w io.Writer, title string, v interface{}) {
	fmt.Fprintf(w, "\n=== %s ===\n", title)
	data, _ := json.MarshalIndent(v, "", "  ")
	fmt.Fprintf(w, "%s\n", string(data))
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>droidaudit Report - {{.Device.Model}}</title>
<style>
{{.CSS}}
</style>
</head>
<body>
<div class="container">
<header>
<h1>🛡️ droidaudit Privacy & Security Report</h1>
<div class="meta">
<span class="badge">{{.Device.Model}}</span>
<span class="badge">{{.Device.AndroidVer}}</span>
<span class="badge">{{.Device.Kernel}}</span>
{{if .Device.Rooted}}<span class="badge rooted">🔓 Rooted</span>{{else}}<span class="badge">🔒 Not Rooted</span>{{end}}
<span class="badge">{{.Timestamp}}</span>
</div>
</header>

<div class="summary-grid">
<div class="summary-card critical">
<div class="count">{{.Summary.Critical}}</div>
<div class="label">Critical</div>
</div>
<div class="summary-card warning">
<div class="count">{{.Summary.Warning}}</div>
<div class="label">Warning</div>
</div>
<div class="summary-card info">
<div class="count">{{.Summary.Info}}</div>
<div class="label">Info</div>
</div>
<div class="summary-card passed">
<div class="count">{{.Summary.Passed}}</div>
<div class="label">Passed</div>
</div>
</div>

{{if .Permissions}}<section class="section">
<h2>🔐 Permissions ({{len .Permissions.Findings}} findings)</h2>
{{range .Permissions.Findings}}
<div class="finding {{.Severity}}">
<div class="finding-header">
<span class="pkg">{{.Package}}</span>
<span class="severity {{.Severity}}">{{.Severity}}</span>
</div>
<div class="finding-name">{{.Name}}</div>
<div class="finding-perms">
{{range .Permissions}}<span class="perm">{{.}}</span>{{end}}
</div>
<div class="finding-desc">{{.Description}}</div>
</div>
{{end}}
</section>{{end}}

{{if .Trackers}}<section class="section">
<h2>🕵️ Trackers ({{len .Trackers.Findings}} findings)</h2>
{{range .Trackers.Findings}}
<div class="finding {{.Severity}}">
<div class="finding-header">
<span class="pkg">{{.Package}}</span>
<span class="severity {{.Severity}}">{{.Severity}}</span>
</div>
<div class="finding-name">{{.Name}}</div>
<div class="finding-trackers">
{{range .Trackers}}<span class="tracker">{{.}}</span>{{end}}
</div>
<div class="finding-cats">
Categories: {{range .Categories}}<span class="cat">{{.}}</span>{{end}}
</div>
</div>
{{end}}
</section>{{end}}

{{if .Network}}<section class="section">
<h2>🌐 Network ({{len .Network.Findings}} findings)</h2>
{{range .Network.Findings}}
<div class="finding {{.Severity}}">
<div class="finding-header">
<span class="type">{{.Type}}</span>
<span class="severity {{.Severity}}">{{.Severity}}</span>
</div>
<div class="finding-detail">{{.Detail}}</div>
<div class="finding-desc">{{.Description}}</div>
</div>
{{end}}
</section>{{end}}

{{if .Bloatware}}<section class="section">
<h2>📦 Bloatware ({{len .Bloatware.Findings}} findings)</h2>
{{range .Bloatware.Findings}}
<div class="finding {{.Severity}}">
<div class="finding-header">
<span class="pkg">{{.Package}}</span>
<span class="severity {{.Severity}}">{{.Severity}}</span>
</div>
<div class="finding-name">{{.Name}}</div>
<div class="finding-desc">{{.Description}}</div>
<div class="finding-meta">
Category: {{.Category}} | Safe to remove: {{if .SafeToRemove}}✅ Yes{{else}}❌ No{{end}}
</div>
</div>
{{end}}
</section>{{end}}

{{if .Settings}}<section class="section">
<h2>⚙️ Settings ({{len .Settings.Findings}} findings)</h2>
{{range .Settings.Findings}}
<div class="finding {{.Severity}}">
<div class="finding-header">
<span class="setting">{{.Setting}}</span>
<span class="severity {{.Severity}}">{{.Severity}}</span>
</div>
<div class="finding-detail">Current: {{.Value}} | Expected: {{.Expected}}</div>
<div class="finding-desc">{{.Description}}</div>
{{if .FixHint}}<div class="fix-hint">💡 {{.FixHint}}</div>{{end}}
</div>
{{end}}
</section>{{end}}

<footer>
<p>Generated by <a href="https://github.com/hash/droidaudit">droidaudit</a> v{{.Version}} on {{.Timestamp}}</p>
<p>Free, open-source, privacy-first Android auditing.</p>
</footer>
</div>
</body>
</html>`

var css = `
* { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #1a1a2e; background: #f5f5f7; margin: 0; padding: 20px; }
.container { max-width: 900px; margin: 0 auto; background: white; border-radius: 16px; box-shadow: 0 4px 24px rgba(0,0,0,0.08); overflow: hidden; }
header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 32px; }
header h1 { margin: 0 0 16px; font-size: 1.8rem; font-weight: 700; }
.meta { display: flex; flex-wrap: wrap; gap: 8px; }
.badge { background: rgba(255,255,255,0.2); padding: 6px 12px; border-radius: 20px; font-size: 0.85rem; }
.badge.rooted { background: #ffd700; color: #1a1a2e; }
.summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; padding: 24px; background: #fafafa; border-bottom: 1px solid #eee; }
.summary-card { background: white; border-radius: 12px; padding: 20px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.04); }
.summary-card.critical { border-top: 4px solid #e74c3c; }
.summary-card.warning { border-top: 4px solid #f39c12; }
.summary-card.info { border-top: 4px solid #3498db; }
.summary-card.passed { border-top: 4px solid #27ae60; }
.count { font-size: 2.5rem; font-weight: 700; line-height: 1; }
.summary-card.critical .count { color: #e74c3c; }
.summary-card.warning .count { color: #f39c12; }
.summary-card.info .count { color: #3498db; }
.summary-card.passed .count { color: #27ae60; }
.label { font-size: 0.9rem; color: #666; margin-top: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
.section { padding: 24px; border-bottom: 1px solid #eee; }
.section:last-of-type { border-bottom: none; }
.section h2 { margin: 0 0 20px; font-size: 1.3rem; color: #2c3e50; display: flex; align-items: center; gap: 10px; }
.finding { background: #fafafa; border-radius: 10px; padding: 16px; margin-bottom: 12px; border-left: 4px solid #ddd; transition: transform 0.15s; }
.finding:hover { transform: translateX(4px); }
.finding.critical { border-left-color: #e74c3c; }
.finding.warning { border-left-color: #f39c12; }
.finding.info { border-left-color: #3498db; }
.finding.passed { border-left-color: #27ae60; opacity: 0.6; }
.finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; flex-wrap: wrap; gap: 8px; }
.pkg, .setting, .type { font-family: 'Monaco', 'Consolas', monospace; font-size: 0.85rem; background: #eee; padding: 4px 8px; border-radius: 4px; }
.severity { text-transform: uppercase; font-size: 0.7rem; font-weight: 700; padding: 4px 10px; border-radius: 20px; }
.severity.critical { background: #fdeaea; color: #c0392b; }
.severity.warning { background: #fef5e7; color: #b7950b; }
.severity.info { background: #eaf4fc; color: #2980b9; }
.severity.passed { background: #e8f8f0; color: #1e824c; }
.finding-name { font-weight: 600; margin: 4px 0; color: #2c3e50; }
.finding-perms, .finding-trackers { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0; }
.perm, .tracker { font-family: monospace; font-size: 0.75rem; background: #e8f0fe; color: #1a73e8; padding: 3px 8px; border-radius: 4px; }
.cat { font-size: 0.7rem; background: #ffeaa7; color: #b8860b; padding: 2px 6px; border-radius: 4px; margin-right: 4px; }
.finding-detail { font-family: monospace; font-size: 0.85rem; color: #555; margin: 4px 0; }
.finding-desc { color: #444; font-size: 0.9rem; }
.finding-meta { font-size: 0.8rem; color: #666; margin-top: 8px; }
.fix-hint { background: #e8f8f0; border-radius: 6px; padding: 10px; margin-top: 8px; font-size: 0.85rem; color: #1e824c; }
footer { padding: 24px; text-align: center; color: #888; font-size: 0.85rem; background: #fafafa; }
footer a { color: #667eea; text-decoration: none; }
footer a:hover { text-decoration: underline; }

@media (max-width: 600px) {
.summary-grid { grid-template-columns: repeat(2, 1fr); }
.finding-header { flex-direction: column; align-items: flex-start; }
}
`

func WriteHTML(result *scan.Result, w io.Writer) error {
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}

	data := struct {
		*scan.Result
		CSS    string
		Version string
	}{
		Result:  result,
		CSS:     css,
		Version: "dev",
	}

	return tmpl.Execute(w, data)
}