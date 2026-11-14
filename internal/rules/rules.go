package rules

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Ruleset struct {
	Permissions []PermissionRule `yaml:"permissions"`
	Trackers    map[string]string `yaml:"trackers"`
	Network     NetworkRules     `yaml:"network"`
	Bloatware   map[string]BloatInfo `yaml:"bloatware"`
	Settings    []SettingRule    `yaml:"settings"`

	// Computed maps for fast lookup
	dangerousPerms    map[string]bool
	criticalPerms     map[string]bool
	warningPerms      map[string]bool
	suspiciousPorts   []string
	suspiciousNets    []string
	SuspiciousPorts   []string
	SuspiciousNetworks []string
}

type PermissionRule struct {
	Name        string `yaml:"name"`
	Severity    string `yaml:"severity"` // critical, warning, info
	Description string `yaml:"description"`
}

type NetworkRules struct {
	SuspiciousPorts  []string `yaml:"suspicious_ports"`
	SuspiciousNetworks []string `yaml:"suspicious_networks"`
}

type BloatInfo struct {
	Severity      string `yaml:"severity"`      // critical, warning, info
	Description   string `yaml:"description"`
	SafeToRemove  bool   `yaml:"safe_to_remove"`
	Category      string `yaml:"category"`
}

type SettingRule struct {
	Key         string `yaml:"key"`
	Namespace   string `yaml:"namespace"` // global, secure, system
	Expected    string `yaml:"expected"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
	FixHint     string `yaml:"fix_hint"`
}

func Load(customDir string) (*Ruleset, error) {
	r := &Ruleset{}

	// Load default rules embedded in binary
	if err := r.loadDefaults(); err != nil {
		return nil, err
	}

	// Overlay custom rules if provided
	if customDir != "" {
		if err := r.loadCustom(customDir); err != nil {
			return nil, err
		}
	}

	r.buildIndexes()
	return r, nil
}

func (r *Ruleset) loadDefaults() error {
	// Permissions
	r.Permissions = []PermissionRule{
		{Name: "android.permission.READ_SMS", Severity: "critical", Description: "Can read all SMS messages (2FA codes, private conversations)"},
		{Name: "android.permission.RECEIVE_SMS", Severity: "critical", Description: "Can intercept incoming SMS (2FA bypass)"},
		{Name: "android.permission.SEND_SMS", Severity: "critical", Description: "Can send SMS (premium fraud, spam)"},
		{Name: "android.permission.READ_CALL_LOG", Severity: "critical", Description: "Access to call history"},
		{Name: "android.permission.WRITE_CALL_LOG", Severity: "critical", Description: "Can modify call history"},
		{Name: "android.permission.PROCESS_OUTGOING_CALLS", Severity: "critical", Description: "Can redirect/block outgoing calls"},
		{Name: "android.permission.READ_CONTACTS", Severity: "warning", Description: "Access to all contacts"},
		{Name: "android.permission.WRITE_CONTACTS", Severity: "warning", Description: "Can modify contacts"},
		{Name: "android.permission.GET_ACCOUNTS", Severity: "warning", Description: "Can list all accounts (email, Google, etc.)"},
		{Name: "android.permission.ACCESS_FINE_LOCATION", Severity: "warning", Description: "Precise GPS location"},
		{Name: "android.permission.ACCESS_COARSE_LOCATION", Severity: "warning", Description: "Approximate location"},
		{Name: "android.permission.ACCESS_BACKGROUND_LOCATION", Severity: "critical", Description: "Tracks location when app closed"},
		{Name: "android.permission.CAMERA", Severity: "warning", Description: "Can take photos/videos"},
		{Name: "android.permission.RECORD_AUDIO", Severity: "warning", Description: "Can record microphone"},
		{Name: "android.permission.READ_EXTERNAL_STORAGE", Severity: "warning", Description: "Read all files on storage"},
		{Name: "android.permission.WRITE_EXTERNAL_STORAGE", Severity: "warning", Description: "Write/delete files on storage"},
		{Name: "android.permission.MANAGE_EXTERNAL_STORAGE", Severity: "critical", Description: "Full file access (Android 11+)"},
		{Name: "android.permission.REQUEST_INSTALL_PACKAGES", Severity: "warning", Description: "Can install other apps"},
		{Name: "android.permission.SYSTEM_ALERT_WINDOW", Severity: "warning", Description: "Draw over other apps (overlay attacks)"},
		{Name: "android.permission.BIND_ACCESSIBILITY_SERVICE", Severity: "critical", Description: "Accessibility service (screen reader, keylogger)"},
		{Name: "android.permission.BIND_DEVICE_ADMIN", Severity: "critical", Description: "Device admin (wipe, lock, password policy)"},
		{Name: "android.permission.INTERACT_ACROSS_USERS_FULL", Severity: "critical", Description: "Cross-user interaction (system only)"},
		{Name: "android.permission.READ_PHONE_STATE", Severity: "warning", Description: "Phone state, IMEI, phone number"},
		{Name: "android.permission.CALL_PHONE", Severity: "critical", Description: "Can make calls without confirmation"},
		{Name: "android.permission.ANSWER_PHONE_CALLS", Severity: "critical", Description: "Can answer calls programmatically"},
		{Name: "android.permission.USE_FINGERPRINT", Severity: "info", Description: "Fingerprint authentication"},
		{Name: "android.permission.USE_BIOMETRIC", Severity: "info", Description: "Biometric authentication"},
		{Name: "android.permission.NFC", Severity: "info", Description: "NFC access"},
		{Name: "android.permission.BLUETOOTH_CONNECT", Severity: "info", Description: "Bluetooth connections"},
		{Name: "android.permission.BLUETOOTH_SCAN", Severity: "info", Description: "Bluetooth scanning"},
		{Name: "android.permission.WRITE_SETTINGS", Severity: "warning", Description: "Modify system settings"},
		{Name: "android.permission.WRITE_SECURE_SETTINGS", Severity: "critical", Description: "Modify secure system settings (system only)"},
		{Name: "android.permission.INSTALL_PACKAGES", Severity: "critical", Description: "Install packages (system only)"},
		{Name: "android.permission.DELETE_PACKAGES", Severity: "critical", Description: "Uninstall packages (system only)"},
		{Name: "android.permission.CHANGE_CONFIGURATION", Severity: "warning", Description: "Change system configuration"},
		{Name: "android.permission.MODIFY_AUDIO_SETTINGS", Severity: "info", Description: "Modify audio settings"},
		{Name: "android.permission.READ_CALENDAR", Severity: "warning", Description: "Read calendar events"},
		{Name: "android.permission.WRITE_CALENDAR", Severity: "warning", Description: "Modify calendar events"},
	}

	// Tracker signatures (package/class patterns -> category)
	r.Trackers = map[string]string{
		"google.android.gms.analytics":       "analytics",
		"com.google.firebase.analytics":      "analytics",
		"com.google.android.gms.measurement": "analytics",
		"com.crashlytics":                    "crash_reporting",
		"com.facebook.reactnative":           "analytics",
		"com.appsflyer":                      "attribution",
		"com.adjust":                         "attribution",
		"com.kochava":                        "attribution",
		"com.singular":                       "attribution",
		"com.branch":                         "attribution",
		"com.onesignal":                      "push_notifications",
		"com.airbnb.android.react.maps":      "location",
		"com.google.android.gms.location":    "location",
		"com.amplitude":                      "analytics",
		"com.mixpanel":                       "analytics",
		"com.segment":                        "analytics",
		"com.urbanairship":                   "push_notifications",
		"com.pushwoosh":                      "push_notifications",
		"com.clever_tap":                     "analytics",
		"com.localytics":                     "analytics",
		"com.flurry":                         "analytics",
		"com.chartboost":                     "ads",
		"com.unity3d.ads":                    "ads",
		"com.vungle":                         "ads",
		"com.applovin":                       "ads",
		"com.ironsource":                     "ads",
		"com.facebook.ads":                   "ads",
		"com.google.android.gms.ads":         "ads",
		"com.mopub":                          "ads",
		"com.inmobi":                         "ads",
		"com.adcolony":                       "ads",
		"com.tapjoy":                         "ads",
	}

	// Network rules
	r.Network = NetworkRules{
		SuspiciousPorts: []string{
			":22", ":23", ":3389", ":5900", ":4444", ":1337", ":31337",
			":8080", ":8443", ":9000", ":9001",
		},
		SuspiciousNetworks: []string{
			"10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
			"172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
			"172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
		},
	}

	// Bloatware database (package -> info)
	r.Bloatware = map[string]BloatInfo{
		// Samsung
		"com.samsung.android.bixby.agent":        {Severity: "warning", Description: "Bixby voice assistant", SafeToRemove: true, Category: "assistant"},
		"com.samsung.android.bixby.es.globalaction": {Severity: "info", Description: "Bixby routines", SafeToRemove: true, Category: "assistant"},
		"com.samsung.android.app.spage":          {Severity: "info", Description: "Samsung Free (news feed)", SafeToRemove: true, Category: "bloat"},
		"com.samsung.android.app.watchmanager":   {Severity: "info", Description: "Galaxy Watch manager", SafeToRemove: true, Category: "wearable"},
		"com.samsung.android.hmt.vrsvc":          {Severity: "info", Description: "VR service", SafeToRemove: true, Category: "vr"},
		"com.samsung.android.ardrawing":          {Severity: "info", Description: "AR Drawing", SafeToRemove: true, Category: "ar"},
		"com.samsung.android.arzone":             {Severity: "info", Description: "AR Zone", SafeToRemove: true, Category: "ar"},
		"com.samsung.android.kidsinstaller":      {Severity: "info", Description: "Kids mode installer", SafeToRemove: true, Category: "kids"},
		"com.samsung.android.knox.containercore": {Severity: "warning", Description: "Knox container", SafeToRemove: false, Category: "security"},
		"com.sec.android.app.samsungapps":        {Severity: "info", Description: "Galaxy Store", SafeToRemove: true, Category: "store"},
		"com.samsung.android.app.galaxyfinder":   {Severity: "info", Description: "S Finder", SafeToRemove: true, Category: "search"},

		// Google
		"com.google.android.googlequicksearchbox": {Severity: "info", Description: "Google App/Search", SafeToRemove: false, Category: "search"},
		"com.google.android.apps.maps":           {Severity: "info", Description: "Google Maps", SafeToRemove: false, Category: "maps"},
		"com.google.android.youtube":             {Severity: "info", Description: "YouTube", SafeToRemove: true, Category: "media"},
		"com.google.android.music":               {Severity: "info", Description: "YouTube Music", SafeToRemove: true, Category: "media"},
		"com.google.android.videos":              {Severity: "info", Description: "Google Play Movies", SafeToRemove: true, Category: "media"},
		"com.google.android.apps.photos":         {Severity: "info", Description: "Google Photos", SafeToRemove: false, Category: "photos"},
		"com.google.android.apps.docs":           {Severity: "info", Description: "Google Drive", SafeToRemove: true, Category: "cloud"},
		"com.google.android.gm":                  {Severity: "info", Description: "Gmail", SafeToRemove: false, Category: "email"},

		// Xiaomi/MIUI
		"com.miui.analytics":                     {Severity: "critical", Description: "Xiaomi analytics", SafeToRemove: true, Category: "telemetry"},
		"com.miui.msa.global":                    {Severity: "critical", Description: "MIUI system ads", SafeToRemove: true, Category: "ads"},
		"com.xiaomi.midrop":                      {Severity: "info", Description: "Mi Drop", SafeToRemove: true, Category: "file_transfer"},

		// Facebook/Meta
		"com.facebook.katana":                    {Severity: "warning", Description: "Facebook", SafeToRemove: true, Category: "social"},
		"com.facebook.orca":                      {Severity: "warning", Description: "Messenger", SafeToRemove: true, Category: "social"},
		"com.instagram.android":                  {Severity: "warning", Description: "Instagram", SafeToRemove: true, Category: "social"},
		"com.whatsapp":                           {Severity: "info", Description: "WhatsApp", SafeToRemove: false, Category: "messaging"},

		// Common bloat
		"com.netflix.mediaclient":                {Severity: "info", Description: "Netflix", SafeToRemove: true, Category: "media"},
		"com.spotify.music":                      {Severity: "info", Description: "Spotify", SafeToRemove: true, Category: "media"},
		"com.microsoft.office.word":              {Severity: "info", Description: "Word", SafeToRemove: true, Category: "office"},
		"com.microsoft.office.excel":             {Severity: "info", Description: "Excel", SafeToRemove: true, Category: "office"},
		"com.microsoft.office.powerpoint":        {Severity: "info", Description: "PowerPoint", SafeToRemove: true, Category: "office"},
		"com.adobe.reader":                       {Severity: "info", Description: "Adobe Reader", SafeToRemove: true, Category: "office"},
	}

	return nil
}

func (r *Ruleset) loadCustom(dir string) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return err
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return err
		}

		var custom Ruleset
		if err := yaml.Unmarshal(data, &custom); err != nil {
			return err
		}

		// Merge
		r.Permissions = append(r.Permissions, custom.Permissions...)
		for k, v := range custom.Trackers {
			r.Trackers[k] = v
		}
		r.Network.SuspiciousPorts = append(r.Network.SuspiciousPorts, custom.Network.SuspiciousPorts...)
		r.Network.SuspiciousNetworks = append(r.Network.SuspiciousNetworks, custom.Network.SuspiciousNetworks...)
		for k, v := range custom.Bloatware {
			r.Bloatware[k] = v
		}
		r.Settings = append(r.Settings, custom.Settings...)
	}

	return nil
}

func (r *Ruleset) buildIndexes() {
	r.dangerousPerms = make(map[string]bool)
	r.criticalPerms = make(map[string]bool)
	r.warningPerms = make(map[string]bool)
	r.SuspiciousPorts = r.Network.SuspiciousPorts
	r.SuspiciousNetworks = r.Network.SuspiciousNetworks

	for _, p := range r.Permissions {
		r.dangerousPerms[p.Name] = true
		if p.Severity == "critical" {
			r.criticalPerms[p.Name] = true
		} else if p.Severity == "warning" {
			r.warningPerms[p.Name] = true
		}
	}
}

func (r *Ruleset) IsDangerous(perm string) bool {
	return r.dangerousPerms[perm]
}

func (r *Ruleset) IsCritical(perm string) bool {
	return r.criticalPerms[perm]
}

func (r *Ruleset) IsWarning(perm string) bool {
	return r.warningPerms[perm]
}

func (r *Ruleset) IsSuspicious(perm string) bool {
	return r.dangerousPerms[perm]
}

func (r *Ruleset) GetDescription(perm string) string {
	for _, p := range r.Permissions {
		if p.Name == perm {
			return p.Description
		}
	}
	return "Dangerous permission"
}

func (r *Ruleset) IsCriticalTracker(tracker string) bool {
	critical := []string{"analytics", "attribution", "location"}
	for _, c := range critical {
		if r.Trackers[tracker] == c {
			return true
		}
	}
	return false
}

func Validate(path string) error {
	files, _ := filepath.Glob(filepath.Join(path, "*.yaml"))
	for _, file := range files {
		data, _ := os.ReadFile(file)
		var r Ruleset
		if err := yaml.Unmarshal(data, &r); err != nil {
			return err
		}
	}
	return nil
}