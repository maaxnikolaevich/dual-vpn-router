package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"github.com/maks/dual-vpn-router/dualvpn"
	"github.com/maks/dual-vpn-router/internal/config"
	"github.com/maks/dual-vpn-router/internal/network"
)

var (
	configFile string
	verbose    bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "dual-vpn",
		Short: "Manage two VPN connections simultaneously on Linux",
		Long: `dual-vpn is a tool for managing two VPN connections simultaneously
through Policy Based Routing (PBR).

It solves the problem of using a corporate VPN and a personal VPN
for bypassing internet restrictions at the same time.`,
	}

	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "/etc/dual-vpn/config.yaml", "Configuration file path")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	// Setup command
	setupCmd := &cobra.Command{
		Use:   "setup",
		Short: "Set up dual VPN routing",
		Long:  "Configure split DNS and routing for two VPN connections",
		Run:   runSetup,
	}

	// Cleanup command
	cleanupCmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Clean up dual VPN routing",
		Long:  "Remove all routing rules and DNS configuration",
		Run:   runCleanup,
	}

	// Status command
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show current status",
		Long:  "Display current VPN interfaces and routing status",
		Run:   runStatus,
	}

	// Init command
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize configuration file",
		Long:  "Create default configuration file at /etc/dual-vpn/config.yaml",
		Run:   runInit,
	}

	rootCmd.AddCommand(setupCmd, cleanupCmd, statusCmd, initCmd)

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func runSetup(cmd *cobra.Command, args []string) {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	router := dualvpn.NewRouter(cfg)
	if err := router.Setup(); err != nil {
		log.Fatalf("Failed to setup: %v", err)
	}

	fmt.Println("\nDual VPN routing is now active!")
	fmt.Println("Test it with:")
	fmt.Println("  dig <your.corporate.domain> +short  # Should resolve via corporate DNS")
	fmt.Println("  dig google.com +short  # Should resolve via Google DNS")
}

func runCleanup(cmd *cobra.Command, args []string) {
	cfg, err := loadConfig()
	if err != nil {
		log.Printf("Warning: failed to load config: %v", err)
		cfg = config.DefaultConfig()
	}

	router := dualvpn.NewRouter(cfg)
	if err := router.Cleanup(); err != nil {
		log.Fatalf("Failed to cleanup: %v", err)
	}

	fmt.Println("Cleanup complete!")
}

func runStatus(cmd *cobra.Command, args []string) {
	fmt.Println("VPN Interfaces:")
	interfaces, err := network.GetVPNInterfaces()
	if err != nil {
		log.Printf("Failed to get VPN interfaces: %v", err)
	} else {
		for _, iface := range interfaces {
			status := "DOWN"
			if iface.Up {
				status = "UP"
			}
			fmt.Printf("  - %s: %s (gateway: %s)\n", iface.Name, status, iface.Gateway)
		}
	}

	fmt.Println("\nRouting Rules:")
	output, err := exec.Command("ip", "rule", "list").CombinedOutput()
	if err == nil {
		fmt.Print(string(output))
	}

	fmt.Println("\nCorp Routing Table:")
	output, err = exec.Command("ip", "route", "show", "table", "corp").CombinedOutput()
	if err == nil {
		fmt.Print(string(output))
	}
}

func runInit(cmd *cobra.Command, args []string) {
	cfg := config.DefaultConfig()

	configDir := "/etc/dual-vpn"
	if err := os.MkdirAll(configDir, 0755); err != nil {
		log.Fatalf("Failed to create config directory: %v", err)
	}

	configPath := fmt.Sprintf("%s/config.yaml", configDir)
	if err := config.Save(cfg, configPath); err != nil {
		log.Fatalf("Failed to save config: %v", err)
	}

	fmt.Printf("Configuration file created at: %s\n", configPath)
	fmt.Println("Edit it to match your VPN setup and run:")
	fmt.Println("  sudo dual-vpn setup")
}

func loadConfig() (*config.Config, error) {
	// Check if config file exists, if not use default
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		log.Printf("Config file not found, using defaults")
		return config.DefaultConfig(), nil
	}

	return config.Load(configFile)
}
