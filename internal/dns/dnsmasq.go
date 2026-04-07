package dns

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Dnsmasq manages dnsmasq configuration
type Dnsmasq struct {
	ConfigDir          string
	ConfigFile         string
	PIDFile            string
	LogFile            string
	ResolvedConfigFile string
	BackupResolvConf   string
}

// NewDnsmasq creates a new Dnsmasq manager
func NewDnsmasq() *Dnsmasq {
	return &Dnsmasq{
		ConfigDir:          "/etc/dnsmasq.d",
		ConfigFile:         "/etc/dnsmasq.d/dual-vpn.conf",
		PIDFile:            "/run/dnsmasq/dnsmasq.pid",
		LogFile:            "/var/log/dnsmasq.log",
		ResolvedConfigFile: "/etc/systemd/resolved.conf.d/dual-vpn.conf",
		BackupResolvConf:   "/var/lib/dual-vpn/resolv.conf.backup",
	}
}

// GenerateConfig generates dnsmasq configuration
func (d *Dnsmasq) GenerateConfig(domains []DomainConfig, fallback []string) ([]byte, error) {
	var builder strings.Builder

	builder.WriteString("# Dual-VPN-Router DNS Configuration\n")
	builder.WriteString("# Generated automatically - do not edit manually\n\n")

	builder.WriteString(fmt.Sprintf("listen-address=127.0.0.1\n"))
	builder.WriteString("no-resolv\n")

	// Add domain-specific DNS servers
	for _, domain := range domains {
		for _, server := range domain.Servers {
			builder.WriteString(fmt.Sprintf("server=/%s/%s\n", domain.Name, server))
		}
	}

	// Add fallback DNS
	for _, server := range fallback {
		builder.WriteString(fmt.Sprintf("server=%s\n", server))
	}

	builder.WriteString("\n")
	builder.WriteString("cache-size=1000\n")
	builder.WriteString("no-negcache\n")
	builder.WriteString("log-queries\n")
	builder.WriteString(fmt.Sprintf("log-facility=%s\n", d.LogFile))

	return []byte(builder.String()), nil
}

// WriteConfig writes dnsmasq configuration to file
func (d *Dnsmasq) WriteConfig(config []byte) error {
	// Ensure config directory exists
	if err := os.MkdirAll(d.ConfigDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	return os.WriteFile(d.ConfigFile, config, 0644)
}

// Restart restarts dnsmasq service
func (d *Dnsmasq) Restart() error {
	// Backup original resolv.conf before making any changes
	if err := d.backupResolvConf(); err != nil {
		fmt.Printf("Warning: failed to backup resolv.conf: %v\n", err)
	}

	// Enable dnsmasq
	if err := exec.Command("systemctl", "enable", "dnsmasq").Run(); err != nil {
		return fmt.Errorf("failed to enable dnsmasq: %w", err)
	}

	// Restart dnsmasq
	if err := exec.Command("systemctl", "restart", "dnsmasq").Run(); err != nil {
		return fmt.Errorf("failed to restart dnsmasq: %w", err)
	}

	return nil
}

// Stop stops dnsmasq service
func (d *Dnsmasq) Stop() error {
	return exec.Command("systemctl", "stop", "dnsmasq").Run()
}

// IsRunning checks if dnsmasq is running
func (d *Dnsmasq) IsRunning() bool {
	output, err := exec.Command("systemctl", "is-active", "dnsmasq").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == "active"
}

// RemoveConfig removes the dnsmasq configuration file
func (d *Dnsmasq) RemoveConfig() error {
	if _, err := os.Stat(d.ConfigFile); err == nil {
		return os.Remove(d.ConfigFile)
	}
	return nil
}

// CleanupSystemdResolved removes systemd-resolved configuration and restores default behavior
func (d *Dnsmasq) CleanupSystemdResolved() error {
	// Remove the custom config file
	if _, err := os.Stat(d.ResolvedConfigFile); err == nil {
		if err := os.Remove(d.ResolvedConfigFile); err != nil {
			return fmt.Errorf("failed to remove resolved config: %w", err)
		}
	}

	// Restart systemd-resolved to reload configuration
	if err := exec.Command("systemctl", "restart", "systemd-resolved").Run(); err != nil {
		return fmt.Errorf("failed to restart systemd-resolved: %w", err)
	}

	// Restore original resolv.conf from backup
	if err := d.restoreResolvConf(); err != nil {
		fmt.Printf("Warning: failed to restore resolv.conf: %v\n", err)
	}

	return nil
}

// FullCleanup stops dnsmasq and cleans up all DNS configuration
func (d *Dnsmasq) FullCleanup() error {
	// Stop dnsmasq
	if err := d.Stop(); err != nil {
		fmt.Printf("Warning: failed to stop dnsmasq: %v\n", err)
	}

	// Remove config file
	if err := d.RemoveConfig(); err != nil {
		fmt.Printf("Warning: failed to remove dnsmasq config: %v\n", err)
	}

	// Cleanup systemd-resolved and restore resolv.conf
	if err := d.CleanupSystemdResolved(); err != nil {
		fmt.Printf("Warning: failed to cleanup systemd-resolved: %v\n", err)
	}

	// Clean up backup file
	if _, err := os.Stat(d.BackupResolvConf); err == nil {
		if err := os.Remove(d.BackupResolvConf); err != nil {
			fmt.Printf("Warning: failed to remove backup resolv.conf: %v\n", err)
		}
	}

	return nil
}

// backupResolvConf backs up the original /etc/resolv.conf
func (d *Dnsmasq) backupResolvConf() error {
	// Ensure backup directory exists
	if err := os.MkdirAll("/var/lib/dual-vpn", 0755); err != nil {
		return err
	}

	// Check if backup already exists
	if _, err := os.Stat(d.BackupResolvConf); err == nil {
		return nil // Backup already exists
	}

	// Read current resolv.conf content
	content, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return fmt.Errorf("failed to read resolv.conf: %w", err)
	}

	// Save to backup file
	if err := os.WriteFile(d.BackupResolvConf, content, 0644); err != nil {
		return fmt.Errorf("failed to write backup: %w", err)
	}

	return nil
}

// restoreResolvConf restores the original /etc/resolv.conf from backup
func (d *Dnsmasq) restoreResolvConf() error {
	// Check if backup exists
	if _, err := os.Stat(d.BackupResolvConf); err != nil {
		// No backup, just restore symlink to systemd-resolved
		if err := exec.Command("ln", "-sf", "/run/systemd/resolve/resolv.conf", "/etc/resolv.conf").Run(); err != nil {
			return fmt.Errorf("failed to restore symlink: %w", err)
		}
		return nil
	}

	// Read backup content
	content, err := os.ReadFile(d.BackupResolvConf)
	if err != nil {
		return fmt.Errorf("failed to read backup: %w", err)
	}

	// Write to resolv.conf
	if err := os.WriteFile("/etc/resolv.conf", content, 0644); err != nil {
		return fmt.Errorf("failed to restore resolv.conf: %w", err)
	}

	return nil
}

// DomainConfig represents a domain with its DNS servers
type DomainConfig struct {
	Name    string
	Servers []string
}
