package routing

import (
	"fmt"
	"os/exec"
	"strings"
)

// PBR manages Policy Based Routing
type PBR struct {
	TableName string
	TableID   int
	rtTables  string
}

// NewPBR creates a new PBR manager
func NewPBR(tableName string, tableID int) *PBR {
	return &PBR{
		TableName: tableName,
		TableID:   tableID,
		rtTables:  "/etc/iproute2/rt_tables",
	}
}

// Setup sets up PBR rules and routes
func (p *PBR) Setup(corpGateway, globalGateway string, corpNetworks, corpDNS []string) error {
	// 1. Add routing table to rt_tables
	if err := p.addRoutingTable(); err != nil {
		return fmt.Errorf("failed to add routing table: %w", err)
	}

	// 2. Add default route in corp table
	if err := p.addDefaultRoute(corpGateway); err != nil {
		return fmt.Errorf("failed to add default route: %w", err)
	}

	// 3. Add routes to corp DNS servers
	for _, dns := range corpDNS {
		if err := p.addDNSRoute(dns); err != nil {
			// Log warning but continue - route might already exist
			fmt.Printf("Warning: failed to add DNS route for %s: %v\n", dns, err)
		}
	}

	// 4. Add rules for corp networks
	for _, network := range corpNetworks {
		if err := p.addNetworkRule(network); err != nil {
			return fmt.Errorf("failed to add network rule: %w", err)
		}
	}

	// 5. Mark DNS packets and add fwmark rule
	if err := p.markDNSPackets(corpDNS); err != nil {
		return fmt.Errorf("failed to mark DNS packets: %w", err)
	}

	if err := p.addFwmarkRule(); err != nil {
		return fmt.Errorf("failed to add fwmark rule: %w", err)
	}

	return nil
}

// Cleanup cleans up PBR rules and routes
// Only removes dual-vpn specific rules, not system rules
func (p *PBR) Cleanup() error {
	// Remove rules for our table specifically
	output, err := exec.Command("ip", "rule", "list").CombinedOutput()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			// Remove rules that use our table
			if strings.Contains(line, "lookup") && strings.Contains(line, p.TableName) {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					// Skip priority, use the rest
					args := []string{"rule", "del"}
					for i := 1; i < len(parts); i++ {
						args = append(args, parts[i])
					}
					_ = exec.Command("ip", args...).Run()
				}
			}
		}
	}

	// Flush corp table only
	_ = exec.Command("ip", "route", "flush", "table", p.TableName).Run()

	// Remove our DNS marking rules from mangle
	p.removeDNSMarkRules()

	return nil
}

// removeDNSMarkRules removes DNS marking rules from iptables mangle
func (p *PBR) removeDNSMarkRules() {
	// Remove from OUTPUT chain
	p.removeMangleRules("OUTPUT", "-d", "53")

	// Remove fwmark rule for our table
	output, _ := exec.Command("ip", "rule", "list").CombinedOutput()
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "fwmark 1") && strings.Contains(line, "lookup") && strings.Contains(line, p.TableName) {
			_ = exec.Command("ip", "rule", "del", "fwmark", "1", "lookup", p.TableName).Run()
		}
	}
}

// removeMangleRules removes mangle rules matching pattern
func (p *PBR) removeMangleRules(chain string, patterns ...string) {
	output, _ := exec.Command("iptables", "-t", "mangle", "-L", chain, "--line-numbers").CombinedOutput()
	lines := strings.Split(string(output), "\n")

	// Collect line numbers to delete (in reverse order)
	var lineNumbers []int
	for _, line := range lines {
		match := true
		for _, pattern := range patterns {
			if !strings.Contains(line, pattern) {
				match = false
				break
			}
		}
		if match && strings.Contains(line, "MARK") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				var num int
				if _, err := fmt.Sscanf(parts[0], "%d", &num); err == nil {
					lineNumbers = append(lineNumbers, num)
				}
			}
		}
	}

	// Delete in reverse order to maintain line numbers
	for i := len(lineNumbers) - 1; i >= 0; i-- {
		_ = exec.Command("iptables", "-t", "mangle", "-D", chain, fmt.Sprintf("%d", lineNumbers[i])).Run()
	}
}

// addRoutingTable adds the routing table to /etc/iproute2/rt_tables
func (p *PBR) addRoutingTable() error {
	// Check if table already exists
	output, err := exec.Command("grep", p.TableName, p.rtTables).CombinedOutput()
	if err == nil && len(output) > 0 {
		return nil // Already exists
	}

	// Add table
	return exec.Command("sh", "-c",
		fmt.Sprintf("echo '%d %s' >> %s", p.TableID, p.TableName, p.rtTables),
	).Run()
}

// RemoveRoutingTable removes the routing table from /etc/iproute2/rt_tables
func (p *PBR) RemoveRoutingTable() error {
	output, _ := exec.Command("grep", "-v", p.TableName, p.rtTables).CombinedOutput()
	return exec.Command("sh", "-c", fmt.Sprintf("echo '%s' > %s", string(output), p.rtTables)).Run()
}

// addDefaultRoute adds default route to corp table
func (p *PBR) addDefaultRoute(gateway string) error {
	return exec.Command("ip", "route", "add", "default", "via", gateway, "table", p.TableName).Run()
}

// addDNSRoute adds route to DNS server
func (p *PBR) addDNSRoute(dns string) error {
	return exec.Command("ip", "route", "add", dns, "table", p.TableName).Run()
}

// addNetworkRule adds rule for corporate network
func (p *PBR) addNetworkRule(network string) error {
	output, err := exec.Command("ip", "rule", "add", "to", network, "lookup", p.TableName).CombinedOutput()
	if err != nil {
		// Check if rule already exists
		if strings.Contains(string(output), "RTNETLINK answers: File exists") {
			return nil // Rule already exists, not an error
		}
		return err
	}
	return nil
}

// markDNSPackets marks DNS packets destined to corp DNS
func (p *PBR) markDNSPackets(corpDNS []string) error {
	for _, dns := range corpDNS {
		// Check if rule already exists (ignore error)
		_ = exec.Command("iptables", "-t", "mangle", "-D", "OUTPUT",
			"-p", "udp", "--dport", "53", "-d", dns,
			"-j", "MARK", "--set-mark", "1").Run()
		_ = exec.Command("iptables", "-t", "mangle", "-D", "OUTPUT",
			"-p", "tcp", "--dport", "53", "-d", dns,
			"-j", "MARK", "--set-mark", "1").Run()

		// UDP
		if err := exec.Command("iptables", "-t", "mangle", "-A", "OUTPUT",
			"-p", "udp", "--dport", "53", "-d", dns,
			"-j", "MARK", "--set-mark", "1").Run(); err != nil {
			return err
		}
		// TCP
		if err := exec.Command("iptables", "-t", "mangle", "-A", "OUTPUT",
			"-p", "tcp", "--dport", "53", "-d", dns,
			"-j", "MARK", "--set-mark", "1").Run(); err != nil {
			return err
		}
	}
	return nil
}

// addFwmarkRule adds rule for marked packets
func (p *PBR) addFwmarkRule() error {
	output, err := exec.Command("ip", "rule", "add", "fwmark", "1", "lookup", p.TableName).CombinedOutput()
	if err != nil {
		// Check if rule already exists
		if strings.Contains(string(output), "RTNETLINK answers: File exists") {
			return nil // Rule already exists, not an error
		}
		return err
	}
	return nil
}

// GetRouteTable returns the route table for the interface
func (p *PBR) GetRouteTable(iface string) (map[string]string, error) {
	output, err := exec.Command("ip", "route", "show", "dev", iface).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get route table: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	routes := make(map[string]string)

	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			routes[parts[0]] = strings.Join(parts[1:], " ")
		}
	}

	return routes, nil
}
