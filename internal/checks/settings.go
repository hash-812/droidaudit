package checks

import (
	"strings"

	"github.com/hash/droidaudit/internal/rules"
)

type SettingsResult struct {
	Critical int               `json:"critical"`
	Warning  int               `json:"warning"`
	Info     int               `json:"info"`
	Passed   int               `json:"passed"`
	Findings []SettingsFinding `json:"findings"`
}

type SettingsFinding struct {
	Setting     string `json:"setting"`
	Value       string `json:"value"`
	Expected    string `json:"expected"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	FixHint     string `json:"fix_hint,omitempty"`
}

func CheckSettings(a Adaptor, r *rules.Ruleset) *SettingsResult {
	res := &SettingsResult{}

	checks := []func(Adaptor, *rules.Ruleset) []SettingsFinding{
		checkDebugging,
		checkUnknownSources,
		checkEncryption,
		checkLockscreen,
		checkLocation,
		checkBackup,
		checkNFC,
		checkUSBConfig,
		checkDeveloperOptions,
		checkAccessibility,
		checkDeviceAdmin,
	}

	for _, check := range checks {
		findings := check(a, r)
		res.Findings = append(res.Findings, findings...)
	}

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

func checkDebugging(a Adaptor, r *rules.Ruleset) []SettingsFinding {
	var findings []SettingsFinding

	out, _ := a.Run("shell", "settings", "get", "global", "adb_enabled")
	if strings.TrimSpace(out) == "1" {
		findings = append(findings, SettingsFinding{
			Setting:     "adb_enabled",
			Value:       "1",
			Expected:    "0",
			Severity:    "critical",
			Description: "USB Debugging is enabled",
			FixHint:     "Settings > Developer options > USB debugging",
		})
	} else {
		findings = append(findings, SettingsFinding{
			Setting:  "adb_enabled",
			Value:    "0",
			Expected: "0",
			Severity: "passed",
		})
	}

	out, _ = a.Run("shell", "settings", "get", "global", "development_settings_enabled")
	if strings.TrimSpace(out) == "1" {
		findings = append(findings, SettingsFinding{
			Setting:     "development_settings_enabled",
			Value:       "1",
			Expected:    "0",
			Severity:    "warning",
			Description: "Developer options enabled",
		})
	}

	return findings
}

func checkUnknownSources(a Adaptor, r *rules.Ruleset) []SettingsFinding {
	var findings []SettingsFinding

	out, _ := a.Run("shell", "settings", "get", "secure", "install_non_market_apps")
	if strings.TrimSpace(out) == "1" {
		findings = append(findings, SettingsFinding{
			Setting:     "install_non_market_apps",
			Value:       "1",
			Expected:    "0",
			Severity:    "warning",
			Description: "Install from unknown sources allowed",
			FixHint:     "Settings > Security > Unknown sources",
		})
	}

	return findings
}

func checkEncryption(a Adaptor, r *rules.Ruleset) []SettingsFinding {
	var findings []SettingsFinding

	out, _ := a.RunRoot("getprop", "ro.crypto.state")
	if !strings.Contains(out, "encrypted") {
		findings = append(findings, SettingsFinding{
			Setting:     "encryption",
			Value:       strings.TrimSpace(out),
			Expected:    "encrypted",
			Severity:    "critical",
			Description: "Device storage not encrypted",
		})
	}

	return findings
}

func checkLockscreen(a Adaptor, r *rules.Ruleset) []SettingsFinding {
	var findings []SettingsFinding

	out, _ := a.Run("shell", "locksettings", "get-disabled")
	if strings.TrimSpace(out) == "true" || strings.Contains(out, "null") {
		findings = append(findings, SettingsFinding{
			Setting:     "lockscreen",
			Value:       "disabled",
			Expected:    "enabled",
			Severity:    "critical",
			Description: "No lockscreen (PIN/pattern/password/biometric)",
			FixHint:     "Settings > Security > Screen lock",
		})
	}

	return findings
}

func checkLocation(a Adaptor, r *rules.Ruleset) []SettingsFinding {
	var findings []SettingsFinding

	out, _ := a.Run("shell", "settings", "get", "secure", "location_mode")
	mode := strings.TrimSpace(out)
	if mode != "0" && mode != "off" {
		findings = append(findings, SettingsFinding{
			Setting:     "location_mode",
			Value:       mode,
			Expected:    "0 (off)",
			Severity:    "warning",
			Description: "Location services enabled",
			FixHint:     "Settings > Location > Off",
		})
	}

	return findings
}

func checkBackup(a Adaptor, r *rules.Ruleset) []SettingsFinding {
	var findings []SettingsFinding

	out, _ := a.Run("shell", "bmgr", "enabled")
	if strings.Contains(out, "true") {
		findings = append(findings, SettingsFinding{
			Setting:     "backup_enabled",
			Value:       "true",
			Expected:    "false",
			Severity:    "info",
			Description: "Google Backup enabled (uploads app data to Google)",
			FixHint:     "Settings > Google > Backup > Off",
		})
	}

	return findings
}

func checkNFC(a Adaptor, r *rules.Ruleset) []SettingsFinding {
	var findings []SettingsFinding

	out, _ := a.Run("shell", "settings", "get", "secure", "nfc_on")
	if strings.TrimSpace(out) == "1" {
		findings = append(findings, SettingsFinding{
			Setting:     "nfc_on",
			Value:       "1",
			Expected:    "0",
			Severity:    "info",
			Description: "NFC enabled",
			FixHint:     "Settings > Connected devices > NFC > Off",
		})
	}

	return findings
}

func checkUSBConfig(a Adaptor, r *rules.Ruleset) []SettingsFinding {
	var findings []SettingsFinding

	out, _ := a.Run("shell", "settings", "get", "global", "usb_configuration")
	if strings.TrimSpace(out) != "none" && strings.TrimSpace(out) != "charging" {
		findings = append(findings, SettingsFinding{
			Setting:     "usb_configuration",
			Value:       strings.TrimSpace(out),
			Expected:    "charging",
			Severity:    "warning",
			Description: "USB mode not set to charge-only",
			FixHint:     "Notification shade > USB preferences > Charge only",
		})
	}

	return findings
}

func checkDeveloperOptions(a Adaptor, r *rules.Ruleset) []SettingsFinding {
	var findings []SettingsFinding

	risky := []string{
		"stay_on_while_plugged_in",
		"allow_mock_location",
		"enable_view_attribute_inspection",
		"show_touches",
		"pointer_location",
	}

	for _, setting := range risky {
		out, _ := a.Run("shell", "settings", "get", "global", setting)
		if strings.TrimSpace(out) == "1" {
			findings = append(findings, SettingsFinding{
				Setting:     setting,
				Value:       "1",
				Expected:    "0",
				Severity:    "info",
				Description: "Developer option enabled: " + setting,
			})
		}
	}

	return findings
}

func checkAccessibility(a Adaptor, r *rules.Ruleset) []SettingsFinding {
	var findings []SettingsFinding

	out, _ := a.Run("shell", "settings", "get", "secure", "enabled_accessibility_services")
	if strings.TrimSpace(out) != "" && strings.TrimSpace(out) != "0" {
		findings = append(findings, SettingsFinding{
			Setting:     "accessibility_services",
			Value:       strings.TrimSpace(out),
			Expected:    "none",
			Severity:    "warning",
			Description: "Accessibility services enabled (can read screen, keystrokes)",
			FixHint:     "Settings > Accessibility > Installed services",
		})
	}

	return findings
}

func checkDeviceAdmin(a Adaptor, r *rules.Ruleset) []SettingsFinding {
	var findings []SettingsFinding

	out, _ := a.Run("shell", "dpm", "list-device-owners")
	if !strings.Contains(out, "No device owners") && strings.TrimSpace(out) != "" {
		findings = append(findings, SettingsFinding{
			Setting:     "device_owner",
			Value:       strings.TrimSpace(out),
			Expected:    "none",
			Severity:    "critical",
			Description: "Device owner app set (full device control)",
			FixHint:     "Settings > Security > Device admin apps",
		})
	}

	out, _ = a.Run("shell", "dpm", "list-profile-owners")
	if !strings.Contains(out, "No profile owners") && strings.TrimSpace(out) != "" {
		findings = append(findings, SettingsFinding{
			Setting:     "profile_owner",
			Value:       strings.TrimSpace(out),
			Expected:    "none",
			Severity:    "warning",
			Description: "Profile owner app set (work profile control)",
		})
	}

	return findings
}