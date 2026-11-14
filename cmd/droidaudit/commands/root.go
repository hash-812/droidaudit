package commands

import (
	"fmt"
	"os"
	"runtime"

	"github.com/hash/droidaudit/internal/report"
	"github.com/hash/droidaudit/internal/rules"
	"github.com/hash/droidaudit/internal/scan"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	Version string
	Commit  string
	Date    string

	cfgFile      string
	serial       string
	outputFile   string
	outputFormat string
	rulesDir     string
	verbose      bool
	jsonOutput   bool
)

var rootCmd = &cobra.Command{
	Use:   "droidaudit",
	Short: "Android Privacy & Security Auditor",
	Long: `droidaudit scans your Android device via ADB and generates a privacy/security report.

It checks:
  • App permissions (dangerous, suspicious, tracker-related)
  • Network connections and DNS
  • System settings (encryption, debugging, unknown sources)
  • Pre-installed bloatware with removal safety scores
  • Tracker libraries embedded in apps`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return viper.BindPFlags(cmd.Flags())
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return runScan(cmd)
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("droidaudit %s\n", Version)
		fmt.Printf("  Commit: %s\n", Commit)
		fmt.Printf("  Built:  %s\n", Date)
		fmt.Printf("  Go:     %s\n", runtime.Version())
		fmt.Printf("  OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	},
}

var listDevicesCmd = &cobra.Command{
	Use:   "devices",
	Short: "List connected ADB devices",
	RunE: func(cmd *cobra.Command, args []string) error {
		devices, err := scan.ListDevices()
		if err != nil {
			return err
		}
		if len(devices) == 0 {
			fmt.Println("No devices connected")
			return nil
		}
		for _, d := range devices {
			status := "online"
			if d.State != "device" {
				status = d.State
			}
			fmt.Printf("%s\t%s\t%s\n", d.Serial, d.Model, status)
		}
		return nil
	},
}

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage rulesets",
	RunE: func(cmd *cobra.Command, args []string) error {
		return listRules()
	},
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available rulesets",
	RunE: func(cmd *cobra.Command, args []string) error {
		return listRules()
	},
}

var rulesValidateCmd = &cobra.Command{
	Use:   "validate [path]",
	Short: "Validate ruleset syntax",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := "."
		if len(args) > 0 {
			path = args[0]
		}
		return rules.Validate(path)
	},
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: $HOME/.droidaudit.yaml)")
	rootCmd.PersistentFlags().StringVarP(&serial, "serial", "s", "", "device serial (required if multiple devices)")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "output file (default: stdout)")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "format", "f", "html", "output format: html, json, txt")
	rootCmd.PersistentFlags().StringVar(&rulesDir, "rules", "", "custom rules directory")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output raw JSON to stdout")

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(listDevicesCmd)
	rootCmd.AddCommand(rulesCmd)
	rulesCmd.AddCommand(rulesListCmd)
	rulesCmd.AddCommand(rulesValidateCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, _ := os.UserHomeDir()
		viper.AddConfigPath(home)
		viper.SetConfigName(".droidaudit")
		viper.SetConfigType("yaml")
	}
	viper.AutomaticEnv()
	viper.ReadInConfig()
}

func Execute() error {
	return rootCmd.Execute()
}

func runScan(cmd *cobra.Command) error {
	if serial == "" {
		devices, err := scan.ListDevices()
		if err != nil {
			return err
		}
		if len(devices) == 0 {
			return fmt.Errorf("no devices connected")
		}
		if len(devices) > 1 {
			return fmt.Errorf("multiple devices connected, specify --serial")
		}
		serial = devices[0].Serial
	}

	r, err := rules.Load(rulesDir)
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}

	if verbose {
		fmt.Printf("Scanning device %s...\n", serial)
	}

	ctx := &scan.Context{
		Serial:   serial,
		Rules:    r,
		Verbose:  verbose,
		Progress: verbose,
	}

	result, err := scan.Run(ctx)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if jsonOutput {
		return report.WriteJSON(result, os.Stdout)
	}

	var out *os.File
	if outputFile == "" {
		out = os.Stdout
	} else {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("create output: %w", err)
		}
		defer f.Close()
		out = f
	}

	switch outputFormat {
	case "html":
		return report.WriteHTML(result, out)
	case "json":
		return report.WriteJSON(result, out)
	case "txt":
		return report.WriteText(result, out)
	default:
		return fmt.Errorf("unknown format: %s", outputFormat)
	}
}

func listRules() error {
	r, err := rules.Load(rulesDir)
	if err != nil {
		return err
	}
	fmt.Printf("Loaded rulesets:\n")
	fmt.Printf("  Permissions: %d rules\n", len(r.Permissions))
	fmt.Printf("  Trackers:    %d signatures\n", len(r.Trackers))
	fmt.Printf("  Network:     %d ports, %d networks\n", len(r.Network.SuspiciousPorts), len(r.Network.SuspiciousNetworks))
	fmt.Printf("  Bloatware:   %d packages\n", len(r.Bloatware))
	fmt.Printf("  Settings:    %d checks\n", len(r.Settings))
	return nil
}