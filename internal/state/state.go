package state

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// StateManager manages saving and restoring network state
type StateManager struct {
	SavedState *NetworkState
}

// NetworkState represents the saved network configuration
type NetworkState struct {
	IPRules      []string
	MainRoutes   []string
	CorpRoutes   []string
	MangleRules  []string
	ResolvedFile string
}

// NewStateManager creates a new StateManager
func NewStateManager() *StateManager {
	return &StateManager{}
}

// Save saves the current network state
func (sm *StateManager) Save(tableName string, tableID int) error {
	state := &NetworkState{}

	// Save IP rules
	rules, err := sm.getIPRules()
	if err != nil {
		return fmt.Errorf("failed to save IP rules: %w", err)
	}
	state.IPRules = rules

	// Save main routing table routes
	routes, err := sm.getRoutes("main")
	if err != nil {
		return fmt.Errorf("failed to save main routes: %w", err)
	}
	state.MainRoutes = routes

	// Save corp routing table routes (if exists)
	corpRoutes, err := sm.getRoutes(tableName)
	if err == nil {
		state.CorpRoutes = corpRoutes
	}

	// Save iptables mangle rules
	mangleRules, err := sm.getMangleRules()
	if err != nil {
		return fmt.Errorf("failed to save mangle rules: %w", err)
	}
	state.MangleRules = mangleRules

	// Save systemd-resolved config file (if exists)
	if content, err := os.ReadFile("/etc/systemd/resolved.conf.d/dual-vpn.conf"); err == nil {
		state.ResolvedFile = string(content)
	}

	sm.SavedState = state

	// Also save to file for persistence
	if err := sm.SaveToFile(GetStatePath()); err != nil {
		fmt.Printf("Warning: failed to save state to file: %v\n", err)
	}

	return nil
}

// Restore restores the saved network state
func (sm *StateManager) Restore(tableName string, tableID int) error {
	// Try to load from file first if no in-memory state
	if sm.SavedState == nil {
		if err := sm.LoadFromFile(GetStatePath()); err != nil {
			// No saved state, just cleanup our rules
			return sm.CleanupOnly(tableName)
		}
	}

	if sm.SavedState == nil {
		return sm.CleanupOnly(tableName)
	}

	// Flush dual-vpn specific rules first
	sm.cleanupRulesOnly(tableName)

	// Restore IP rules (skip dual-vpn ones)
	for _, rule := range sm.SavedState.IPRules {
		if strings.TrimSpace(rule) == "" {
			continue
		}
		// Skip rules that look like our corporate rules
		if sm.isOurRule(rule, tableName, tableID) {
			continue
		}
		if err := sm.addIPRule(rule); err != nil {
			fmt.Printf("Warning: failed to restore IP rule '%s': %v\n", rule, err)
		}
	}

	// Restore main routes
	for _, route := range sm.SavedState.MainRoutes {
		if strings.TrimSpace(route) == "" {
			continue
		}
		// Skip local routes (auto-generated)
		if strings.HasPrefix(route, "local ") || strings.HasPrefix(route, "broadcast ") {
			continue
		}
		if err := sm.addRoute("main", route); err != nil {
			fmt.Printf("Warning: failed to restore main route '%s': %v\n", route, err)
		}
	}

	// Restore iptables mangle rules (skip our DNS marks)
	for _, rule := range sm.SavedState.MangleRules {
		if strings.TrimSpace(rule) == "" {
			continue
		}
		// Skip policy and chain definitions
		if strings.HasPrefix(rule, "-P") || strings.HasPrefix(rule, "-N") {
			continue
		}
		// Skip our DNS marking rules
		if sm.isOurMangleRule(rule) {
			continue
		}
		if err := sm.addMangleRule(rule); err != nil {
			fmt.Printf("Warning: failed to restore mangle rule '%s': %v\n", rule, err)
		}
	}

	return nil
}

// CleanupOnly removes only dual-vpn rules without restoring anything
func (sm *StateManager) CleanupOnly(tableName string) error {
	return sm.cleanupRulesOnly(tableName)
}

// cleanupRulesOnly removes only dual-vpn specific rules
func (sm *StateManager) cleanupRulesOnly(tableName string) error {
	// Remove rules for our table using specific deletion
	output, _ := exec.Command("ip", "rule", "list").CombinedOutput()
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.Contains(line, "lookup") && strings.Contains(line, tableName) {
			if err := sm.deleteIPRule(line); err != nil {
				fmt.Printf("Warning: failed to delete IP rule '%s': %v\n", line, err)
			}
		}
	}

	// Flush corp table
	_ = exec.Command("ip", "route", "flush", "table", tableName).Run()

	// Remove DNS marking rules from mangle
	sm.removeMangleRules()

	return nil
}

// isOurRule checks if a rule is a dual-vpn rule
func (sm *StateManager) isOurRule(rule, tableName string, tableID int) bool {
	if strings.Contains(rule, "lookup") && strings.Contains(rule, tableName) {
		return true
	}
	if strings.Contains(rule, "fwmark") && strings.Contains(rule, "lookup") && strings.Contains(rule, tableName) {
		return true
	}
	if strings.Contains(rule, fmt.Sprintf("lookup %d", tableID)) {
		return true
	}
	return false
}

// isOurMangleRule checks if a mangle rule is our DNS marking rule
func (sm *StateManager) isOurMangleRule(rule string) bool {
	if !strings.Contains(rule, "MARK") {
		return false
	}
	if strings.Contains(rule, "53") && (strings.Contains(rule, "tcp") || strings.Contains(rule, "udp")) {
		return true
	}
	return false
}

// getIPRules returns current IP rules
func (sm *StateManager) getIPRules() ([]string, error) {
	output, err := exec.Command("ip", "rule", "list").CombinedOutput()
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(string(output)), "\n"), nil
}

// addIPRule adds an IP rule
func (sm *StateManager) addIPRule(rule string) error {
	parts := strings.Fields(rule)
	if len(parts) < 2 {
		return nil
	}
	// Parse the rule: "0: from all lookup local" -> "rule add from all lookup local"
	if parts[0] == "0:" || parts[0] == "32766:" || parts[0] == "32767:" {
		// Default rules, reconstruct
		parts = parts[1:]
	}
	return exec.Command("ip", append([]string{"rule", "add"}, parts...)...).Run()
}

// deleteIPRule deletes an IP rule
func (sm *StateManager) deleteIPRule(rule string) error {
	parts := strings.Fields(rule)
	if len(parts) < 2 {
		return nil
	}
	// Skip the priority number at the beginning
	parts = parts[1:]
	return exec.Command("ip", append([]string{"rule", "del"}, parts...)...).Run()
}

// getRoutes returns routes for a specific table
func (sm *StateManager) getRoutes(table string) ([]string, error) {
	output, err := exec.Command("ip", "route", "show", "table", table).CombinedOutput()
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(string(output)), "\n"), nil
}

// addRoute adds a route to a specific table
func (sm *StateManager) addRoute(table, route string) error {
	parts := strings.Fields(route)
	if len(parts) < 1 {
		return nil
	}
	args := []string{"route", "add"}
	args = append(args, parts...)
	args = append(args, "table", table)
	return exec.Command("ip", args...).Run()
}

// getMangleRules returns iptables mangle rules
func (sm *StateManager) getMangleRules() ([]string, error) {
	output, err := exec.Command("iptables", "-t", "mangle", "-S").CombinedOutput()
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(string(output)), "\n"), nil
}

// addMangleRule adds an iptables mangle rule
func (sm *StateManager) addMangleRule(rule string) error {
	// Convert -S format to -A format
	parts := strings.Fields(rule)
	if len(parts) < 2 {
		return nil
	}
	if parts[0] == "-P" || parts[0] == "-N" {
		// Skip default policies and custom chains
		return nil
	}
	// Replace -S with -A
	parts[0] = "-A"
	args := []string{"-t", "mangle"}
	args = append(args, parts...)
	return exec.Command("iptables", args...).Run()
}

// removeMangleRules removes DNS marking rules from mangle table
func (sm *StateManager) removeMangleRules() {
	// Get current rules
	output, _ := exec.Command("iptables", "-t", "mangle", "-L", "OUTPUT", "--line-numbers").CombinedOutput()
	lines := strings.Split(string(output), "\n")

	// Collect line numbers to delete (in reverse order)
	var lineNumbers []int
	for _, line := range lines {
		if strings.Contains(line, "MARK") && (strings.Contains(line, "udp") || strings.Contains(line, "tcp")) && strings.Contains(line, "53") {
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
		_ = exec.Command("iptables", "-t", "mangle", "-D", "OUTPUT", fmt.Sprintf("%d", lineNumbers[i])).Run()
	}
}

// HasSavedState returns true if state has been saved
func (sm *StateManager) HasSavedState() bool {
	return sm.SavedState != nil
}

// SaveToFile saves state to a file for persistence
func (sm *StateManager) SaveToFile(path string) error {
	if sm.SavedState == nil {
		return fmt.Errorf("no state to save")
	}

	var buf bytes.Buffer

	buf.WriteString("# Dual-VPN-Router State Backup\n")
	buf.WriteString("# Generated automatically - do not edit manually\n\n")

	buf.WriteString("# IP Rules\n")
	for _, rule := range sm.SavedState.IPRules {
		buf.WriteString(rule + "\n")
	}
	buf.WriteString("\n")

	buf.WriteString("# Main Routes\n")
	for _, route := range sm.SavedState.MainRoutes {
		buf.WriteString(route + "\n")
	}
	buf.WriteString("\n")

	buf.WriteString("# Corp Routes\n")
	for _, route := range sm.SavedState.CorpRoutes {
		buf.WriteString(route + "\n")
	}
	buf.WriteString("\n")

	buf.WriteString("# Mangle Rules\n")
	for _, rule := range sm.SavedState.MangleRules {
		buf.WriteString(rule + "\n")
	}

	if sm.SavedState.ResolvedFile != "" {
		buf.WriteString("\n# Resolved Config\n")
		buf.WriteString(sm.SavedState.ResolvedFile)
	}

	// Ensure directory exists
	if err := os.MkdirAll("/var/lib/dual-vpn", 0755); err != nil {
		return err
	}

	return os.WriteFile(path, buf.Bytes(), 0644)
}

// LoadFromFile loads state from a file
func (sm *StateManager) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	state := &NetworkState{}
	lines := strings.Split(string(data), "\n")

	var currentSection string
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		switch {
		case line == "# IP Rules":
			currentSection = "rules"
		case line == "# Main Routes":
			currentSection = "main_routes"
		case line == "# Corp Routes":
			currentSection = "corp_routes"
		case line == "# Mangle Rules":
			currentSection = "mangle"
		case line == "# Resolved Config":
			currentSection = "resolved"
		case strings.HasPrefix(line, "#"):
			continue
		default:
			switch currentSection {
			case "rules":
				state.IPRules = append(state.IPRules, line)
			case "main_routes":
				state.MainRoutes = append(state.MainRoutes, line)
			case "corp_routes":
				state.CorpRoutes = append(state.CorpRoutes, line)
			case "mangle":
				state.MangleRules = append(state.MangleRules, line)
			case "resolved":
				if state.ResolvedFile == "" {
					state.ResolvedFile = line
				} else {
					state.ResolvedFile += "\n" + line
				}
			}
		}
	}

	sm.SavedState = state
	return nil
}

// GetStatePath returns the default state file path
func GetStatePath() string {
	return "/var/lib/dual-vpn/state.backup"
}

// CleanupStateFile removes the state file
func CleanupStateFile() error {
	path := GetStatePath()
	if _, err := os.Stat(path); err == nil {
		return os.Remove(path)
	}
	return nil
}
