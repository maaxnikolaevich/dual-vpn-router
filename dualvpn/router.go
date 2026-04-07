package dualvpn

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/maks/dual-vpn-router/internal/config"
	"github.com/maks/dual-vpn-router/internal/dns"
	"github.com/maks/dual-vpn-router/internal/network"
	"github.com/maks/dual-vpn-router/internal/routing"
	"github.com/maks/dual-vpn-router/internal/state"
)

// Router manages dual VPN routing
type Router struct {
	config     *config.Config
	dnsmasq    *dns.Dnsmasq
	pbr        *routing.PBR
	stateMgr   *state.StateManager
	stateFile  string
}

// NewRouter creates a new Router instance
func NewRouter(cfg *config.Config) *Router {
	return &Router{
		config:    cfg,
		dnsmasq:   dns.NewDnsmasq(),
		pbr:       routing.NewPBR("corp", cfg.Routing.CorpTableID),
		stateMgr:  state.NewStateManager(),
		stateFile: state.GetStatePath(),
	}
}

// Setup sets up dual VPN routing
func (r *Router) Setup() error {
	log.Println("Setting up dual VPN routing...")

	// 1. Save current state BEFORE making any changes
	if err := r.stateMgr.Save(r.pbr.TableName, r.config.Routing.CorpTableID); err != nil {
		log.Printf("Warning: failed to save state: %v", err)
	}

	// 2. Find VPN interfaces by config names
	ifaceNames := make([]string, 0, len(r.config.VPNs))
	for _, vpn := range r.config.VPNs {
		ifaceNames = append(ifaceNames, vpn.Interface)
	}

	var interfaces []network.Interface
	var err error

	if len(ifaceNames) > 0 {
		// Use config-based lookup
		interfaces, err = network.GetInterfacesByName(ifaceNames)
		if err != nil {
			return fmt.Errorf("failed to get VPN interfaces from config: %w", err)
		}
	} else {
		// Auto-detect VPN interfaces
		interfaces, err = network.GetVPNInterfaces()
		if err != nil {
			return fmt.Errorf("failed to get VPN interfaces: %w", err)
		}
	}

	if len(interfaces) < 2 {
		return fmt.Errorf("need at least 2 VPN interfaces, found %d. "+
			"Edit /etc/dual-vpn/config.yaml to specify interface names.", len(interfaces))
	}

	// Match interfaces by type from config
	var corpIface, globalIface *network.Interface
	for i := range interfaces {
		for _, vpn := range r.config.VPNs {
			if interfaces[i].Name == vpn.Interface {
				if vpn.Type == "corporate" {
					corpIface = &interfaces[i]
				} else if vpn.Type == "global" {
					globalIface = &interfaces[i]
				}
			}
		}
	}

	// Fallback: use interface order if no config match
	if corpIface == nil && len(interfaces) > 0 {
		corpIface = &interfaces[0]
	}
	if globalIface == nil && len(interfaces) > 1 {
		globalIface = &interfaces[1]
	}

	if corpIface == nil {
		return fmt.Errorf("corporate VPN interface not found")
	}

	log.Printf("Corporate VPN: %s (gateway: %s)", corpIface.Name, corpIface.Gateway)
	if globalIface != nil {
		log.Printf("Global VPN: %s (gateway: %s)", globalIface.Name, globalIface.Gateway)
	}

	// 3. Setup DNS
	domains := make([]dns.DomainConfig, 0, len(r.config.DNS.Domains))
	for _, d := range r.config.DNS.Domains {
		domains = append(domains, dns.DomainConfig{
			Name:    d.Name,
			Servers: d.Servers,
		})
	}

	dnsConfig, err := r.dnsmasq.GenerateConfig(domains, r.config.DNS.Fallback)
	if err != nil {
		return fmt.Errorf("failed to generate DNS config: %w", err)
	}

	if err := r.dnsmasq.WriteConfig(dnsConfig); err != nil {
		return fmt.Errorf("failed to write DNS config: %w", err)
	}

	if err := r.dnsmasq.Restart(); err != nil {
		return fmt.Errorf("failed to restart dnsmasq: %w", err)
	}

	log.Println("DNS setup complete")

	// 4. Setup PBR
	corpDNS := make([]string, 0)
	for _, d := range r.config.DNS.Domains {
		corpDNS = append(corpDNS, d.Servers...)
	}

	// Use global VPN gateway if available, otherwise use corporate gateway for default routing
	globalGateway := ""
	if globalIface != nil {
		globalGateway = globalIface.Gateway
	}

	if err := r.pbr.Setup(corpIface.Gateway, globalGateway, r.config.Routing.CorpNetworks, corpDNS); err != nil {
		return fmt.Errorf("failed to setup PBR: %w", err)
	}

	log.Println("PBR setup complete")

	// 5. Setup systemd-resolved
	if err := r.setupSystemdResolved(); err != nil {
		log.Printf("Warning: failed to setup systemd-resolved: %v", err)
	}

	log.Println("Dual VPN routing setup complete!")
	return nil
}

// Cleanup cleans up dual VPN routing and restores original state
// Uses transactional cleanup with best-effort rollback on errors
func (r *Router) Cleanup() error {
	log.Println("Cleaning up dual VPN routing...")

	var cleanupErrors []error
	var dnsCleaned bool

	// Step 1: Cleanup DNS FIRST (stop dnsmasq and restore original resolv.conf)
	// This ensures DNS is restored to defaults before any routing changes
	if err := r.dnsmasq.FullCleanup(); err != nil {
		log.Printf("Warning: failed to cleanup DNS: %v", err)
		cleanupErrors = append(cleanupErrors, fmt.Errorf("DNS cleanup: %w", err))
	} else {
		dnsCleaned = true
	}

	// Step 2: Restore original network state (after DNS is restored)
	if err := r.stateMgr.Restore(r.pbr.TableName, r.config.Routing.CorpTableID); err != nil {
		log.Printf("Warning: failed to restore state: %v", err)
		// Fall back to cleanup only if restore fails
		if err := r.stateMgr.CleanupOnly(r.pbr.TableName); err != nil {
			log.Printf("Warning: failed to cleanup rules: %v", err)
			cleanupErrors = append(cleanupErrors, fmt.Errorf("routing cleanup: %w", err))
		}
	}

	// Step 3: Remove routing table entry
	if err := r.pbr.RemoveRoutingTable(); err != nil {
		log.Printf("Warning: failed to remove routing table entry: %v", err)
		cleanupErrors = append(cleanupErrors, fmt.Errorf("routing table removal: %w", err))
	}

	// Step 4: Cleanup state file
	if err := state.CleanupStateFile(); err != nil {
		log.Printf("Warning: failed to cleanup state file: %v", err)
		cleanupErrors = append(cleanupErrors, fmt.Errorf("state file cleanup: %w", err))
	}

	// Report results
	if len(cleanupErrors) > 0 {
		log.Printf("Cleanup completed with %d error(s)", len(cleanupErrors))
		if dnsCleaned {
			log.Println("Note: DNS was successfully restored - system should have default DNS resolution")
		} else {
			log.Println("Warning: DNS restoration failed - you may need to manually restore /etc/resolv.conf")
		}
	} else {
		log.Println("Cleanup complete!")
	}

	if len(cleanupErrors) > 0 {
		return fmt.Errorf("cleanup completed with errors: %v", cleanupErrors)
	}
	return nil
}

// setupSystemdResolved configures systemd-resolved to use dnsmasq
func (r *Router) setupSystemdResolved() error {
	// Create systemd-resolved config directory
	if err := execCommand("mkdir", "-p", "/etc/systemd/resolved.conf.d"); err != nil {
		return err
	}

	// Write config
	config := `[Resolve]
DNS=127.0.0.1
FallbackDNS=8.8.8.8 8.8.4.4
`

	domains := ""
	for _, d := range r.config.DNS.Domains {
		domains += fmt.Sprintf(" ~%s", d.Name)
	}
	config += fmt.Sprintf("Domains=%s\n", domains)

	if err := writeToFile("/etc/systemd/resolved.conf.d/dual-vpn.conf", config); err != nil {
		return err
	}

	// Restart systemd-resolved
	if err := execCommand("systemctl", "restart", "systemd-resolved"); err != nil {
		return err
	}

	// Update resolv.conf symlink
	if err := execCommand("ln", "-sf", "/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"); err != nil {
		return err
	}

	return nil
}

// execCommand executes a command
func execCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w (output: %s)", name, err, string(output))
	}
	return nil
}

// writeToFile writes content to a file
func writeToFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}
