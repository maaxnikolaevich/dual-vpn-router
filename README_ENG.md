# dual-vpn-router

**VPN split tunneling for Linux.**

Choose which traffic goes through which tunnel and which goes straight out. No hand-editing `AllowedIPs`, `ip rule` tables or systemd-resolved.

![Main window](docs/screenshots/01-overview.png)

## The problem it solves

When two VPNs are up on one machine — a work one and a personal one — both try to claim the default route. What follows is familiar: all your internet leaves through the corporate tunnel, or internal domains stop resolving, or connectivity drops entirely until you disconnect one of them.

By hand this is fixed with `AllowedIPs` in WireGuard, `route-nopull` in OpenVPN, separate routing tables and per-interface domains in systemd-resolved. It works — and then falls apart after every tunnel reconnect or resume from suspend.

This tool expresses the same thing declaratively: rules are written once, and a daemon holds the state and restores it whenever a tunnel comes back up.

Use it when you need to:

- keep a work VPN and a personal VPN connected at the same time;
- reach corporate subnets and internal domains without routing the whole internet there;
- spread traffic across several tunnels by destination.

## Features

- **Policy based routing** — CIDR lists are routed into a chosen tunnel, everything else goes direct
- **Split DNS** — a domain resolves through its own DNS servers, and the queries to those servers travel through the right tunnel
- **Fail-closed** — a rule's traffic can be dropped while its tunnel is down, so it never leaks onto the open network
- **Tunnel control** — brings NetworkManager, WireGuard and AmneziaWG profiles up and down
- **Auto-detection** — existing VPN profiles are discovered for you, and interfaces are picked up again after a reconnect
- **GUI and CLI** — a desktop app on top of the same daemon the command line talks to
- **YAML config** — human-readable, reviewable and portable

## A tour of the interface

### 1. Main window

![Main window](docs/screenshots/01-overview.png)

On the left are your tunnels and their state: profile type, interface, gateway. **Direct** is listed alongside them as the no-tunnel route.

On the right are two lists of rules. **Routes** send subnets into a tunnel, **DNS** overrides resolution for individual domains. Any rule can be toggled, or dragged onto a different tunnel to re-target it.

The **Routing** switch in the header is the master toggle: it removes everything the tool installed into the system, without touching the VPN connections themselves.

### 2. Add a tunnel

![Add VPN](docs/screenshots/02-add-tunnel.png)

Profiles are discovered automatically: NetworkManager connections and configs under `/etc/wireguard` and `/etc/amnezia`. Ones you have already added are greyed out, so a profile cannot be added twice. Pick a profile, give the tunnel a name, and rules will refer to it by that name.

### 3. New route

![New route](docs/screenshots/03-add-route.png)

A routing rule is a list of subnets plus the tunnel they go into. Destinations are comma-separated CIDRs, and `Route via` selects a tunnel or `direct`.

The **Block this traffic while the tunnel is down** checkbox enables fail-closed behaviour: if the tunnel drops, packets to those subnets are discarded instead of falling back to your normal connection. Worth enabling for corporate networks.

### 4. New domain

![New domain](docs/screenshots/04-add-domain.png)

This is where split DNS is configured. `Domain` is the zone that needs special resolution, `DNS servers` are the addresses that serve it, and `Reach these servers via` is the tunnel the queries themselves travel through.

That last field matters: internal DNS servers are usually only reachable from inside the corporate network, so queries must go through the corporate tunnel even when the domain resolves to a public address.

## Installation

```bash
git clone https://github.com/maaxnikolaevich/dual-vpn-router.git
cd dual-vpn-router
sudo ./packaging/install.sh
```

The script builds both binaries, installs them into `/usr/local/bin`, creates the `dual-vpn` group, adds the current user to it, enables the systemd unit and installs the desktop entry.

The group is what lets the GUI drive the daemon without asking for a password on every toggle. **Log out and back in after the first install**, otherwise the group membership will not apply and the GUI cannot reach the daemon.

Build dependencies: `golang-go`, `libgtk-4-dev`, `libadwaita-1-dev`, `libgirepository1.0-dev`, `dnsmasq`. The script checks for them before building.

### Manually

```bash
go build -o dual-vpn ./cmd/dual-vpn
go build -o dual-vpn-gui ./cmd/dual-vpn-gui
```

## Quick start

```bash
# 1. Create a configuration
sudo dual-vpn init

# 2. Edit it for your tunnels and networks
sudo nano /etc/dual-vpn/config.yaml

# 3. Apply
sudo dual-vpn start

# 4. Check
dual-vpn status
```

Or launch `dual-vpn-gui` and add tunnels and rules through the interface — the configuration is written for you.

The daemon brings up the tunnels it is told to manage, so there is no need to connect your VPNs beforehand. It periodically reconciles the system against the configuration and restores routes after a tunnel reconnects.

On exit the daemon deliberately leaves routing in place: otherwise a restart or crash would silently drop your traffic out of its tunnel and onto the open network. To remove everything it installed, run `dual-vpn stop`.

## Commands

| Command | Description |
|---------|-------------|
| `dual-vpn init` | Write a default configuration file |
| `dual-vpn status` | Show tunnels, routing rules and DNS overrides |
| `dual-vpn start` | Apply routing and DNS |
| `dual-vpn stop` | Remove everything this tool installed |
| `dual-vpn apply` | Re-converge the system on the configuration |
| `dual-vpn daemon` | Run the control daemon (requires root) |
| `dual-vpn tunnel up\|down <name>` | Bring a tunnel up or down |
| `dual-vpn rule enable\|disable <id>` | Enable or disable a routing rule |
| `dual-vpn rule target <id> <tunnel\|direct>` | Route a rule through a different tunnel |
| `dual-vpn dns enable\|disable <domain>` | Enable or disable a domain override |

The old `setup` and `cleanup` still work as aliases for `start` and `stop`.

Global flags: `--config` (defaults to `/etc/dual-vpn/config.yaml`) and `--socket` (the daemon control socket).

## Configuration

`sudo dual-vpn init` writes a placeholder config to `/etc/dual-vpn/config.yaml`. You must replace the placeholders with your own values.

```yaml
version: 2

dns:
    listen_addr: 127.0.0.1
    fallback:
        - 8.8.8.8
        - 8.8.4.4

tunnels:
    - name: corp                  # the name rules refer to
      kind: nm                    # nm | wg-quick | awg-quick | manual
      profile: corporate-vpn      # NetworkManager profile or .conf name
      table_id: 200               # its own routing table, unique per tunnel
      auto_detect: true
    - name: global
      kind: wg-quick              # /etc/wireguard/wg0.conf
      profile: wg0
      table_id: 201
      auto_detect: true

rules:
    - id: corp-networks
      target: corp                # a tunnel name, or direct
      cidrs:
        - 10.0.0.0/8
        - 172.16.0.0/12
      enabled: true
      fail_closed: true           # drop this traffic while the tunnel is down
      comment: Internal networks

dns_rules:
    - domain: corporate.example.com
      servers:
        - 192.168.1.1
      via: corp                   # tunnel used to reach those DNS servers
      enabled: true
```

### What you must change

1. **`tunnels[].profile`** — your real profile names. For `nm` it is the connection name from `nmcli connection show`; for `wg-quick` the filename in `/etc/wireguard` without the extension; for `awg-quick` the same under `/etc/amnezia/amneziawg`.
2. **`rules[].cidrs`** — the subnets that should travel through the tunnel.
3. **`dns_rules`** — your internal domains and the DNS servers that serve them.

### Tunnel kinds

| `kind` | Driven by |
|--------|-----------|
| `nm` | A NetworkManager profile via `nmcli` |
| `wg-quick` | `/etc/wireguard/<profile>.conf` via `wg-quick` |
| `awg-quick` | `/etc/amnezia/amneziawg/<profile>.conf` via `awg-quick` (AmneziaWG) |
| `manual` | Only observed; the tool never brings it up or down |

### Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `dns.listen_addr` | Where dnsmasq listens for queries | `127.0.0.1` |
| `dns.fallback` | DNS servers for every other domain | `8.8.8.8` |
| `tunnels[].name` | Tunnel name that rules refer to | `corp` |
| `tunnels[].kind` | How the tunnel is driven | `wg-quick` |
| `tunnels[].profile` | Profile or config name | `wg0` |
| `tunnels[].table_id` | Routing table ID, unique per tunnel | `200` |
| `tunnels[].auto_detect` | Detect the interface automatically | `true` |
| `rules[].id` | Rule identifier | `corp-networks` |
| `rules[].target` | Destination tunnel, or `direct` | `corp` |
| `rules[].cidrs` | Subnets the rule covers | `10.0.0.0/8` |
| `rules[].fail_closed` | Block traffic while the tunnel is down | `true` |
| `dns_rules[].domain` | Domain with custom resolution | `corp.example.com` |
| `dns_rules[].servers` | DNS servers for that domain | `192.168.1.1` |
| `dns_rules[].via` | Tunnel used to reach those servers | `corp` |

Version 1 configs (the old `vpns:` and `routing.corp_networks` schema) are read and migrated automatically.

## How it works

1. **Routing** — each tunnel gets its own routing table, and `ip rule` steers the rules' subnets into it
2. **DNS** — dnsmasq resolves the listed domains through their servers, and an fwmark pushes those queries into the right tunnel
3. **Daemon** — holds the state, periodically reconciles the system against the config and repairs routes after a tunnel reconnects
4. **Control socket** — a unix socket owned by the `dual-vpn` group, used by both the CLI and the GUI

## Requirements

- Linux (Ubuntu/Debian/Arch)
- systemd
- dnsmasq
- iproute2, iptables
- NetworkManager — for `nm` tunnels
- wireguard-tools — for `wg-quick`
- GTK 4 and libadwaita — for the GUI

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Keywords

split tunneling, vpn split tunnel, linux, vpn, pbr, policy based routing, dual vpn, split routing, two vpn at the same time, ip routing, dns routing, split dns, wireguard split tunnel, openvpn split tunnel, amneziawg, раздельное туннелирование vpn, подключить два впн одновременно, два vpn на linux, корпоративный vpn и личный vpn одновременно
