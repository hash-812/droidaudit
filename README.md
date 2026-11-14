# droidaudit 🛡️

**Free, open-source Android privacy & security auditor.** Scan your device via ADB and get a beautiful report showing exactly what your apps can access, what trackers they contain, network connections, bloatware, and insecure settings.

![droidaudit demo](https://img.shields.io/badge/demo-HTML%20Report-blue)
[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-AGPL--3.0-orange)](LICENSE)
[![Build](https://github.com/hash/droidaudit/actions/workflows/ci.yaml/badge.svg)](https://github.com/hash/droidaudit/actions)

---

## Features

| Check | What It Finds |
|-------|---------------|
| 🔐 **Permissions** | Dangerous permissions (SMS, contacts, location, microphone, camera, accessibility, device admin) |
| 🕵️ **Trackers** | Analytics, crash reporting, attribution, ads, push notifications embedded in apps |
| 🌐 **Network** | Open ports, suspicious connections, non-standard DNS, VPN status |
| 📦 **Bloatware** | Pre-installed apps safe to remove, duplicate functionality apps |
| ⚙️ **Settings** | USB debugging, unknown sources, encryption, lockscreen, location, backup, NFC, device admins |

## Quick Start

```bash
# Install (Linux/macOS)
curl -fsSL https://github.com/hash/droidaudit/releases/latest/download/droidaudit-linux-amd64 -o droidaudit
chmod +x droidaudit

# Or build from source
git clone https://github.com/hash/droidaudit
cd droidaudit
go build ./cmd/droidaudit

# Enable USB debugging on your phone, connect via USB
# Run scan
./droidaudit scan -o report.html
# Open report.html in your browser
```

## Usage

```bash
# List connected devices
droidaudit devices

# Scan with defaults (HTML report to stdout)
droidaudit scan > report.html

# Save to file
droidaudit scan -o report.html

# JSON output for scripting
droidaudit scan -f json -o report.json

# Text output for terminal
droidaudit scan -f txt

# Specify device serial (if multiple connected)
droidaudit scan -s <serial>

# Verbose output
droidaudit scan -v

# Use custom rules directory
droidaudit scan --rules ./my-rules

# Show version
droidaudit version

# List loaded rulesets
droidaudit rules list

# Validate custom rules
droidaudit rules validate ./my-rules
```

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| **HTML** | `-f html` | Visual report, shareable, color-coded severities |
| **JSON** | `-f json` | CI/CD, scripting, further processing |
| **Text** | `-f txt` | Quick terminal view, piping |

## Understanding Results

### Severity Levels

| Level | Meaning | Action |
|-------|---------|--------|
| 🔴 **Critical** | Immediate privacy/security risk | Fix immediately |
| 🟡 **Warning** | Potential risk, review needed | Review & decide |
| 🔵 **Info** | Informational, low risk | Optional |
| 🟢 **Passed** | Secure/expected configuration | No action |

### Example Findings

**Critical Permission:**
```
Package: com.random.flashlight
Permission: android.permission.READ_SMS
Description: Can read all SMS messages (2FA codes, private conversations)
```

**Tracker:**
```
Package: com.example.game
Trackers: com.google.firebase.analytics, com.facebook.reactnative
Categories: analytics, attribution
```

**Network:**
```
Type: open_port
Detail: 0.0.0.0:8080
Severity: warning
Description: Listening port: 0.0.0.0:8080
```

**Bloatware:**
```
Package: com.samsung.android.bixby.agent
Name: Bixby Voice Assistant
Severity: warning
Safe to remove: ✅ Yes
Category: assistant
```

**Settings:**
```
Setting: adb_enabled
Value: 1 (enabled)
Expected: 0 (disabled)
Severity: critical
Fix: Settings > Developer options > USB debugging
```

## Custom Rules

Create `~/.droidaudit.yaml` or use `--rules ./my-rules`:

```yaml
# my-rules/permissions.yaml
permissions:
  - name: "android.permission.CUSTOM_PERMISSION"
    severity: "critical"
    description: "Custom dangerous permission"

# my-rules/bloatware.yaml
bloatware:
  "com.mycompany.bloatapp":
    severity: "warning"
    description: "Company bloatware"
    safe_to_remove: true
    category: "bloat"

# my-rules/network.yaml
network:
  suspicious_ports:
    - ":9999"
  suspicious_networks:
    - "192.168.100."
```

## Requirements

- **Android device** with USB debugging enabled
- **ADB** installed (`android-tools` / `platform-tools`)
- **Go 1.23+** (for building from source)

### Enable USB Debugging
1. Settings → About Phone → Tap "Build Number" 7 times
2. Settings → Developer Options → USB Debugging → ON
3. Connect via USB → Allow debugging on phone

## Installation

### Pre-built Binaries
Download from [Releases](https://github.com/hash/droidaudit/releases)

### From Source
```bash
git clone https://github.com/hash/droidaudit
cd droidaudit
go build -ldflags="-s -w" -o droidaudit ./cmd/droidaudit
```

### Arch Linux (AUR)
```bash
yay -S droidaudit-git
```

## Privacy

**droidaudit runs entirely on your computer.** No data leaves your machine. It only reads information already accessible via ADB. No network requests are made during scanning.

## Contributing

1. Fork the repo
2. Create a feature branch
3. Add tests for new checks
4. Ensure `go test ./...` passes
5. Submit a PR

### Adding New Checks
1. Create `internal/checks/newcheck.go`
2. Implement `CheckNewCheck(Adaptor, *Ruleset) *NewCheckResult`
3. Add to `scan.Run()` in `internal/scan/scan.go`
4. Add severity counting to `calculateSummary()`
5. Add rendering in `internal/report/report.go`

## Roadmap

- [ ] Root-only checks (system partitions, SELinux, kernel config)
- [ ] CI/CD GitHub Action (`droidaudit-action`)
- [ ] Web dashboard for fleet management
- [ ] Compliance packs (GDPR, HIPAA, PCI-DSS)
- [ ] iOS support (via `ideviceinstaller`)
- [ ] Plugin system for custom checks

## License

AGPL-3.0 — Free for personal and commercial use. See [LICENSE](LICENSE).

> **Why AGPL?** Ensures improvements to the hosted/service version stay open. You can use it freely; if you run it as a service for others, share your changes.

## Support

- 🐛 [Issues](https://github.com/hash/droidaudit/issues) — Bug reports, feature requests
- 💬 [Discussions](https://github.com/hash/droidaudit/discussions) — Questions, ideas
- ☕ [Buy me a coffee](https://paypal.me/yourname) — If this helped you

---

**Made with ❤️ for Android privacy.**