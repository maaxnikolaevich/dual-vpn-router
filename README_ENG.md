# dual-vpn-router

Manage two VPN connections simultaneously on Linux through (Policy Based Routing).

## Features

- ✅ **Split DNS** - Route DNS queries through different servers based on domain
- ✅ **Policy Based Routing** - Route traffic through different VPN connections
- ✅ **Auto-detection** - Automatically detect VPN interfaces
- ✅ **Easy CLI** - Simple command-line interface
- ✅ **YAML Config** - Human-readable configuration

## Problem Solved

This tool solves the problem of using a corporate VPN and a personal VPN for bypassing internet restrictions at the same time. Perfect for:

- Remote workers who need access to corporate resources
- Users in regions with internet restrictions
- Anyone needing simultaneous VPN connections

## Installation

```bash
# Clone the repository
git clone https://github.com/maks/dual-vpn-router.git
cd dual-vpn-router

# Install deps
go mod tidy

# Build
go build -o dual-vpn ./cmd

# Install (optional)
sudo cp dual-vpn /usr/local/bin/
sudo chmod +x /usr/local/bin/dual-vpn
```

## Quick Start

```bash
# 1. Initialize configuration
sudo dual-vpn init

# 2. Edit configuration to match your VPN setup
sudo nano /etc/dual-vpn/config.yaml

# 3. Connect your VPNs (use your VPN client first!)
#    - Corporate VPN connection
#    - Global VPN connection
#    Make sure BOTH VPNs are connected before proceeding!

# 4. Setup routing
sudo dual-vpn setup

# 5. Check status
dual-vpn status

# 6. Cleanup when done (or disconnect VPNs)
sudo dual-vpn cleanup
```

## Important: VPN Connection Order

### Starting Up (Correct Order)
1. **Connect your VPNs first** using your VPN client (WireGuard, OpenVPN, etc.)
   - Connect corporate VPN
   - Connect global VPN
2. **Verify both VPNs are up** (check with `sudo dual-vpn status`)
3. **Then run `sudo dual-vpn setup`**

### Shutting Down (Correct Order)
1. **Run `sudo dual-vpn cleanup` first**
   - This restores DNS to original state
   - This removes all routing rules
2. **Then disconnect your VPNs** using your VPN client

### Why This Order Matters

The script creates temporary DNS and routing configurations. If you disconnect VPNs **before** running cleanup:

- DNS queries may fail (pointing to VPN DNS servers that are no longer reachable)
- Routing rules may remain active (pointing to disconnected VPN interfaces)
- Network may be in inconsistent state

**Always run `cleanup` BEFORE disconnecting VPNs!**

## Configuration

**IMPORTANT**: You must manually edit the configuration file with your actual corporate DNS servers, domains, and network ranges. The default configuration contains placeholder values.

Run `sudo dual-vpn init` to create a default config at `/etc/dual-vpn/config.yaml`, then edit it:

```bash
sudo nano /etc/dual-vpn/config.yaml
```

### Required Changes

1. **`dns.domains`**: Replace with your corporate domain(s)
   - `name`: Your corporate domain (e.g., `company.internal`)
   - `servers`: Your corporate DNS server IP addresses

2. **`routing.corp_networks`**: Add your corporate network ranges
   - These networks will be routed through corporate VPN
   - Common ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`

3. **`vpns.interface`**: Check your VPN interface names
   - Run `ip link show` after connecting VPNs to see interface names
   - Common names: `tun0`, `wg0`, `ppp0`

### Example Configuration

```yaml
# ===== YOU MUST CHANGE THESE =====
dns:
    listen_addr: 127.0.0.1:53  # OK: Leave as is
    fallback:
        - 8.8.8.8               # OK: Leave as is (public DNS)
        - 8.8.4.4               # OK: Leave as is (public DNS)
    domains:
        - name: corporate.example.com  # CHANGE: Your corporate domain
          servers:
            - 192.168.1.1              # CHANGE: Your corporate DNS server IP
            - 192.168.1.2              # CHANGE: Your corporate DNS server IP (if you have)

routing:
    corp_table_id: 200          # OK: Leave as is
    corp_networks:
        - 10.0.0.0/8            # OK: Keep if your company uses these ranges
        - 172.16.0.0/12         # OK: Keep if your company uses these ranges
        - 192.168.0.0/16        # OK: Keep if your company uses these ranges

vpns:
    - name: corporate           # OK: Leave as is
      interface: tun0           # CHECK: Run 'ip link show' to verify your interface name
      auto_detect: true         # OK: Leave as is
      type: corporate           # OK: Leave as is
    - name: global              # OK: Leave as is
      interface: wg0            # CHECK: Run 'ip link show' to verify your interface name
      auto_detect: true         # OK: Leave as is
      type: global              # OK: Leave as is
```

### Configuration Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `dns.listen_addr` | Where dnsmasq listens for DNS queries | `127.0.0.1:53` |
| `dns.fallback` | Default DNS servers for non-corporate domains | `8.8.8.8` |
| `dns.domains[].name` | Corporate domain name | `company.internal` |
| `dns.domains[].servers` | Corporate DNS server IPs | `192.168.1.1` |
| `routing.corp_table_id` | Routing table ID for corporate traffic | `200` |
| `routing.corp_networks` | Networks routed through corporate VPN | `10.0.0.0/8` |
| `vpns[].interface` | VPN interface name | `tun0` |
| `vpns[].type` | VPN type: `corporate` or `global` | `corporate` |

## How It Works

1. **DNS Layer**: Uses dnsmasq to route DNS queries to different servers based on domain
2. **Routing Layer**: Uses PBR to route traffic through different VPN interfaces
3. **Auto Setup**: NetworkManager dispatcher for automatic configuration

## Commands

| Command | Description |
|---------|-------------|
| `dual-vpn init` | Create default configuration file |
| `dual-vpn setup` | Set up dual VPN routing (run AFTER VPNs are connected) |
| `dual-vpn cleanup` | Remove all routing rules and restore DNS (run BEFORE disconnecting VPNs) |
| `dual-vpn status` | Show current status |

## Do I Need to Manually Manage VPN Connections?

**No, the script does NOT manage VPN connections automatically.** You must:

- **Connect VPNs manually** using your VPN client (NetworkManager, WireGuard, OpenVPN, etc.)
- **Run `dual-vpn setup`** AFTER both VPNs are connected
- **Run `dual-vpn cleanup`** BEFORE disconnecting VPNs

The script only manages DNS and routing configuration, not the VPN connections themselves.

## Requirements

- Linux (Ubuntu/Debian/Arch)
- NetworkManager
- dnsmasq
- systemd-resolved (optional)
- iptables/iproute2

## Important Notes

### Configuration is Manual

The `dual-vpn init` command creates a **placeholder configuration**. You **must** edit it manually:

```bash
sudo dual-vpn init
sudo nano /etc/dual-vpn/config.yaml
```

Without proper configuration, the routing will not work correctly. Make sure to:

1. Set your actual corporate domain(s) in `dns.domains`
2. Set your corporate DNS server IPs in `dns.domains[].servers`
3. Add your corporate network ranges in `routing.corp_networks`
4. Verify VPN interface names match your setup in `vpns[].interface`

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Keywords

linux, vpn, pbr, policy based routing, dual vpn, split routing, подключить два впн одновременно, два впн на одном компьютере, ip routing, dns routing, настройка двух vpn, split dns, политика маршрутизации, два vpn на linux, корпоративный vpn и личный vpn одновременно