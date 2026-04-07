package network

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// Interface represents a network interface
type Interface struct {
	Name    string
	Gateway string
	Type    string // "tunnel", "wireguard", etc.
	Up      bool
}

// GetVPNInterfaces returns active VPN interfaces
// Note: This function lists all VPN-like interfaces. For config-based lookup, use GetInterfacesByName.
func GetVPNInterfaces() ([]Interface, error) {
	var interfaces []Interface

	// Get network interfaces
	output, err := exec.Command("ip", "link", "show").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list interfaces: %w", err)
	}

	lines := strings.Split(string(output), "\n")

	// Regex to match interface lines: e.g., "4: outline-tun0: <...>"
	// Matches: <number>: <interface-name>:
	ifaceRegex := regexp.MustCompile(`^\s*\d+:\s+(\S+):`)

	for _, line := range lines {
		// Try to match interface line
		matches := ifaceRegex.FindStringSubmatch(line)
		if len(matches) < 2 {
			continue
		}

		ifName := matches[1]

		// Check if this is a VPN interface
		if !isVPNInterface(ifName) {
			continue
		}

		// Check if interface is UP
		up := !bytes.Contains([]byte(line), []byte("DOWN"))

		if !up {
		    continue
		}

		// Get gateway
		gateway, err := getGateway(ifName)
		if err != nil {
			gateway = "none"
		}

		// Determine interface type
		ifaceType := "unknown"
		if strings.HasPrefix(ifName, "tun") {
			ifaceType = "tunnel"
		} else if strings.HasPrefix(ifName, "wg") {
			ifaceType = "wireguard"
		} else if strings.HasPrefix(ifName, "test") {
			ifaceType = "test"
		} else if strings.HasPrefix(ifName, "ppp") {
			ifaceType = "ppp"
		} else if strings.HasPrefix(ifName, "tap") {
			ifaceType = "tap"
		}

		interfaces = append(interfaces, Interface{
			Name:    ifName,
			Gateway: gateway,
			Type:    ifaceType,
			Up:      up,
		})
	}

	return interfaces, nil
}

// isVPNInterface checks if an interface name matches VPN patterns
func isVPNInterface(name string) bool {
	vpnPatterns := []string{"tun", "wg", "test", "ppp", "tap"}
	for _, pattern := range vpnPatterns {
		if strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

// GetInterfacesByName returns interfaces matching exact names provided
func GetInterfacesByName(names []string) ([]Interface, error) {
	var interfaces []Interface

	// Get all interfaces
	output, err := exec.Command("ip", "link", "show").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list interfaces: %w", err)
	}

	lines := strings.Split(string(output), "\n")

	// Regex to match interface lines
	ifaceRegex := regexp.MustCompile(`^\s*\d+:\s+(\S+):`)

	// Create a map for quick lookup
	nameMap := make(map[string]bool)
	for _, name := range names {
		nameMap[name] = true
	}

	for _, line := range lines {
		matches := ifaceRegex.FindStringSubmatch(line)
		// Check if interface is not DOWN
		up := !bytes.Contains([]byte(line), []byte("DOWN"))

		if len(matches) < 2{
			continue
		}

        if !up {
            continue
        }

		ifName := matches[1]

		// Check if this interface is in our name map
		if !nameMap[ifName] {
			continue
		}

		// Get gateway
		gateway, err := getGateway(ifName)
		if err != nil {
			gateway = "none"
		}

		ifaceType := "unknown"
		if strings.HasPrefix(ifName, "tun") {
			ifaceType = "tunnel"
		} else if strings.HasPrefix(ifName, "wg") {
			ifaceType = "wireguard"
		}

		interfaces = append(interfaces, Interface{
			Name:    ifName,
			Gateway: gateway,
			Type:    ifaceType,
			Up:      up,
		})

		// Remove from map so we don't process it again
		delete(nameMap, ifName)
	}

	return interfaces, nil
}

// FindInterfaceByName finds interface by exact name
func FindInterfaceByName(name string) (*Interface, error) {
	interfaces, err := GetInterfacesByName([]string{name})
	if err != nil {
		return nil, err
	}

	if len(interfaces) == 0 {
		return nil, fmt.Errorf("interface %s not found", name)
	}

	return &interfaces[0], nil
}

// getGateway returns the gateway for a given interface
func getGateway(iface string) (string, error) {
	output, err := exec.Command("ip", "route", "show", "dev", iface).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get route: %w", err)
	}

	lines := bytes.Split(output, []byte{'\n'})
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("default")) {
			parts := bytes.Fields(line)
			if len(parts) >= 3 {
				return string(parts[2]), nil
			}
		}
	}

	return "", fmt.Errorf("no default gateway found for %s", iface)
}
