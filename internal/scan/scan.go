package scan

import (
	"os/exec"
	"strings"
	"time"

	"github.com/hash/droidaudit/internal/checks"
	"github.com/hash/droidaudit/internal/rules"
)

type Context struct {
	Serial   string
	Rules    *rules.Ruleset
	Verbose  bool
	Progress bool
}

type Result struct {
	Device      DeviceInfo          `json:"device"`
	Timestamp   string              `json:"timestamp"`
	Permissions *checks.PermResult  `json:"permissions"`
	Trackers    *checks.TrackerResult `json:"trackers"`
	Network     *checks.NetResult   `json:"network"`
	Bloatware   *checks.BloatResult `json:"bloatware"`
	Settings    *checks.SettingsResult `json:"settings"`
	Summary     Summary             `json:"summary"`
}

type DeviceInfo struct {
	Serial       string `json:"serial"`
	Model        string `json:"model"`
	Manufacturer string `json:"manufacturer"`
	AndroidVer   string `json:"android_version"`
	SDK          string `json:"sdk"`
	Kernel       string `json:"kernel"`
	Rooted       bool   `json:"rooted"`
	ABIVersion   string `json:"abi"`
}

type Summary struct {
	Critical int `json:"critical"`
	Warning  int `json:"warning"`
	Info     int `json:"info"`
	Passed   int `json:"passed"`
}

func Run(ctx *Context) (*Result, error) {
	result := &Result{
		Timestamp: time.Now().Format(time.RFC3339),
	}

	device, err := getDeviceInfo(ctx.Serial)
	if err != nil {
		return nil, err
	}
	result.Device = device

	adp := &adaptor{serial: ctx.Serial}

	result.Permissions = checks.CheckPermissions(adp, ctx.Rules)
	result.Trackers = checks.CheckTrackers(adp, ctx.Rules)
	result.Network = checks.CheckNetwork(adp, ctx.Rules)
	result.Bloatware = checks.CheckBloatware(adp, ctx.Rules)
	result.Settings = checks.CheckSettings(adp, ctx.Rules)

	result.Summary = calculateSummary(result)

	return result, nil
}

type adaptor struct {
	serial string
}

func (a *adaptor) Run(cmd ...string) (string, error) {
	args := append([]string{"-s", a.serial}, cmd...)
	return runAdb(args...)
}

func (a *adaptor) RunRoot(cmd ...string) (string, error) {
	args := append([]string{"-s", a.serial, "shell", "su", "-c"}, strings.Join(cmd, " "))
	return runAdb(args...)
}

func (a *adaptor) HasRoot() bool {
	out, _ := a.RunRoot("id")
	return strings.Contains(out, "uid=0")
}

func getDeviceInfo(serial string) (DeviceInfo, error) {
	out, err := runAdb("-s", serial, "shell", "getprop")
	if err != nil {
		return DeviceInfo{}, err
	}

	props := parseProps(out)
	rooted := checkRoot(serial)

	return DeviceInfo{
		Serial:       serial,
		Model:        props["ro.product.model"],
		Manufacturer: props["ro.product.manufacturer"],
		AndroidVer:   props["ro.build.version.release"],
		SDK:          props["ro.build.version.sdk"],
		Kernel:       getKernel(serial),
		Rooted:       rooted,
		ABIVersion:   props["ro.product.cpu.abi"],
	}, nil
}

func parseProps(out string) map[string]string {
	props := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "[") {
			continue
		}
		parts := strings.SplitN(line, "]: [", 2)
		if len(parts) == 2 {
			key := strings.TrimPrefix(parts[0], "[")
			val := strings.TrimSuffix(parts[1], "]")
			props[key] = val
		}
	}
	return props
}

func getKernel(serial string) string {
	out, _ := runAdb("-s", serial, "shell", "cat", "/proc/version")
	fields := strings.Fields(out)
	if len(fields) >= 3 {
		return fields[2]
	}
	return "unknown"
}

func checkRoot(serial string) bool {
	out, _ := runAdb("-s", serial, "shell", "which", "su")
	return strings.TrimSpace(out) != ""
}

func runAdb(args ...string) (string, error) {
	cmd := exec.Command("adb", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

type Device struct {
	Serial string
	Model  string
	State  string
}

func ListDevices() ([]Device, error) {
	out, err := runAdb("devices")
	if err != nil {
		return nil, err
	}
	var devices []Device
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "List of devices") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			devices = append(devices, Device{
				Serial: fields[0],
				State:  fields[1],
				Model:  "",
			})
		}
	}
	// Get model for each device
	for i := range devices {
		modelOut, _ := runAdb("-s", devices[i].Serial, "shell", "getprop", "ro.product.model")
		devices[i].Model = strings.TrimSpace(modelOut)
	}
	return devices, nil
}

func calculateSummary(r *Result) Summary {
	s := Summary{}
	add := func(critical, warning, info, passed int) {
		s.Critical += critical
		s.Warning += warning
		s.Info += info
		s.Passed += passed
	}

	if r.Permissions != nil {
		add(r.Permissions.Critical, r.Permissions.Warning, r.Permissions.Info, r.Permissions.Passed)
	}
	if r.Trackers != nil {
		add(r.Trackers.Critical, r.Trackers.Warning, r.Trackers.Info, r.Trackers.Passed)
	}
	if r.Network != nil {
		add(r.Network.Critical, r.Network.Warning, r.Network.Info, r.Network.Passed)
	}
	if r.Bloatware != nil {
		add(r.Bloatware.Critical, r.Bloatware.Warning, r.Bloatware.Info, r.Bloatware.Passed)
	}
	if r.Settings != nil {
		add(r.Settings.Critical, r.Settings.Warning, r.Settings.Info, r.Settings.Passed)
	}
	return s
}