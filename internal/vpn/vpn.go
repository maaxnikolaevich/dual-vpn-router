package vpn

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/maks/dual-vpn-router/internal/config"
)

// ConnectTimeout bounds a single up/down attempt; VPN handshakes can legitimately take seconds.
const ConnectTimeout = 60 * time.Second

// Status is a point-in-time observation of a configured tunnel.
type Status struct {
	Name      string            `json:"name"`
	Kind      config.TunnelKind `json:"kind"`
	Profile   string            `json:"profile,omitempty"`
	Interface string            `json:"interface,omitempty"`
	Present   bool              `json:"present"`
	Up        bool              `json:"up"`
	Gateway   string            `json:"gateway,omitempty"`
	Addresses []string          `json:"addresses,omitempty"`
	Detail    string            `json:"detail,omitempty"`
}

// Routable reports whether the tunnel can currently carry traffic, which is the
// precondition for installing any routing rule that targets it.
func (s Status) Routable() bool { return s.Present && s.Up }

// Addr is one address on an interface as reported by `ip -j addr show`.
type Addr struct {
	Family string `json:"family"`
	Local  string `json:"local"`
}

// Link is a snapshot of one kernel interface as reported by `ip -j addr show`.
type Link struct {
	IfName    string   `json:"ifname"`
	Flags     []string `json:"flags"`
	OperState string   `json:"operstate"`
	AddrInfo  []Addr   `json:"addr_info"`
}

func (l Link) up() bool {
	// A tunnel with no carrier reports operstate UNKNOWN rather than UP, so the
	// IFF_UP flag is the reliable signal for point-to-point links.
	for _, f := range l.Flags {
		if f == "UP" {
			return l.OperState != "DOWN"
		}
	}
	return false
}

func parseLinks(data []byte) (map[string]Link, error) {
	var links []Link
	if err := json.Unmarshal(data, &links); err != nil {
		return nil, err
	}
	out := make(map[string]Link, len(links))
	for _, l := range links {
		out[l.IfName] = l
	}
	return out, nil
}

type route struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
}

// parseGateway returns the next hop of a default route, if the route set has one.
// WireGuard-style point-to-point links have a default route with no gateway, in
// which case the caller must route by device instead.
func parseGateway(data []byte) (string, error) {
	var routes []route
	if err := json.Unmarshal(data, &routes); err != nil {
		return "", err
	}
	for _, r := range routes {
		if r.Dst == "default" && r.Gateway != "" {
			return r.Gateway, nil
		}
	}
	return "", nil
}

// Manager inspects and drives tunnels. It shells out to ip/nmcli/wg-quick, so
// every mutating call requires root.
type Manager struct{}

func New() *Manager { return &Manager{} }

func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return out, err
		}
		return out, fmt.Errorf("%s: %s", err, msg)
	}
	return out, nil
}

// Links snapshots every interface on the host in one call.
func (m *Manager) Links(ctx context.Context) (map[string]Link, error) {
	out, err := run(ctx, "ip", "-j", "addr", "show")
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	return parseLinks(out)
}

// ResolveInterface determines which kernel interface a tunnel maps to.
func (m *Manager) ResolveInterface(ctx context.Context, t config.Tunnel, links map[string]Link) string {
	if t.Interface != "" {
		return t.Interface
	}

	switch t.Kind {
	case config.KindWGQuick, config.KindAWGQuick:
		// Both flavours of wg-quick name the interface after the config file.
		return t.Profile

	case config.KindNM:
		// Only NetworkManager knows which device this profile owns. Falling
		// back to a guess here would hand the tunnel's routes to an unrelated
		// VPN that happens to be up, so an inactive profile resolves to
		// nothing and is reported as down.
		return m.nmDevice(ctx, t.Profile, links)
	}

	// Autodetect exists for manual tunnels, where the user named no interface.
	if t.AutoDetect {
		return firstTunnelLike(links)
	}
	return ""
}

// nmDevice asks NetworkManager which device a connection profile currently owns.
func (m *Manager) nmDevice(ctx context.Context, profile string, links map[string]Link) string {
	out, err := run(ctx, "nmcli", "-t", "-f", "GENERAL.VPN,GENERAL.DEVICES,IP4.ADDRESS",
		"connection", "show", profile)
	if err != nil {
		return ""
	}
	return nmDeviceFrom(string(out), links)
}

func nmDeviceFrom(out string, links map[string]Link) string {
	var isVPN bool
	var device, addr string

	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || value == "" || value == "--" {
			continue
		}
		switch {
		case key == "GENERAL.VPN":
			isVPN = value == "yes"
		case key == "GENERAL.DEVICES" && device == "":
			device = value
		case strings.HasPrefix(key, "IP4.ADDRESS") && addr == "":
			addr = value
		}
	}

	// For a VPN connection GENERAL.DEVICES names the interface the tunnel runs
	// over, such as the wifi card, not the tunnel itself. Routing a tunnel's
	// table through that device sends its traffic straight out the local link
	// and bypasses the VPN, so the assigned address is the only trustworthy way
	// back to the real interface.
	if isVPN {
		return linkWithAddress(links, addr)
	}
	return device
}

// linkWithAddress finds the interface holding an address given in CIDR form.
func linkWithAddress(links map[string]Link, cidr string) string {
	addr, _, _ := strings.Cut(cidr, "/")
	if addr == "" {
		return ""
	}

	names := make([]string, 0, len(links))
	for name := range links {
		names = append(names, name)
	}
	// Map order is random; sort so a duplicated address resolves the same way.
	sort.Strings(names)

	for _, name := range names {
		for _, a := range links[name].AddrInfo {
			if a.Family == "inet" && a.Local == addr {
				return name
			}
		}
	}
	return ""
}

var tunnelPrefixes = []string{"tun", "wg", "ppp", "tap"}

func firstTunnelLike(links map[string]Link) string {
	names := make([]string, 0, len(links))
	for name := range links {
		names = append(names, name)
	}
	// Map order is random; sort so autodetect picks the same interface every run.
	sort.Strings(names)

	for _, name := range names {
		for _, p := range tunnelPrefixes {
			if strings.HasPrefix(name, p) && links[name].up() {
				return name
			}
		}
	}
	return ""
}

// Interface is a tunnel-like kernel device that could back a manual tunnel.
type Interface struct {
	Name      string   `json:"name"`
	Up        bool     `json:"up"`
	Addresses []string `json:"addresses,omitempty"`
}

// tunnelLike matches on a substring rather than a prefix because tunnels are
// often named after the thing that created them, as in "outline-tun0".
func tunnelLike(name string) bool {
	for _, p := range tunnelPrefixes {
		if strings.Contains(name, p) {
			return true
		}
	}
	return false
}

// ListTunnelInterfaces enumerates devices the GUI can offer as manual tunnels,
// which is the only way to attach to a VPN some other tool brought up.
func (m *Manager) ListTunnelInterfaces(ctx context.Context) ([]Interface, error) {
	links, err := m.Links(ctx)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(links))
	for name := range links {
		if tunnelLike(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	out := make([]Interface, 0, len(names))
	for _, name := range names {
		l := links[name]
		iface := Interface{Name: name, Up: l.up()}
		for _, a := range l.AddrInfo {
			if a.Family == "inet" && a.Local != "" {
				iface.Addresses = append(iface.Addresses, a.Local)
			}
		}
		out = append(out, iface)
	}
	return out, nil
}

// Status observes a single tunnel. links may be nil, in which case it is fetched.
func (m *Manager) Status(ctx context.Context, t config.Tunnel, links map[string]Link) Status {
	st := Status{Name: t.Name, Kind: t.Kind, Profile: t.Profile}

	if links == nil {
		var err error
		links, err = m.Links(ctx)
		if err != nil {
			st.Detail = err.Error()
			return st
		}
	}

	st.Interface = m.ResolveInterface(ctx, t, links)
	if st.Interface == "" {
		st.Detail = "no interface resolved"
		return st
	}

	l, ok := links[st.Interface]
	if !ok {
		st.Detail = "interface not present"
		return st
	}

	st.Present = true
	st.Up = l.up()
	for _, a := range l.AddrInfo {
		if a.Family == "inet" && a.Local != "" {
			st.Addresses = append(st.Addresses, a.Local)
		}
	}

	if st.Up {
		if out, err := run(ctx, "ip", "-j", "route", "show", "dev", st.Interface); err == nil {
			st.Gateway, _ = parseGateway(out)
		}
	}
	return st
}

// StatusAll observes every configured tunnel from a single interface snapshot.
func (m *Manager) StatusAll(ctx context.Context, tunnels []config.Tunnel) []Status {
	links, err := m.Links(ctx)
	if err != nil {
		out := make([]Status, 0, len(tunnels))
		for _, t := range tunnels {
			out = append(out, Status{Name: t.Name, Kind: t.Kind, Profile: t.Profile, Detail: err.Error()})
		}
		return out
	}

	out := make([]Status, 0, len(tunnels))
	for _, t := range tunnels {
		out = append(out, m.Status(ctx, t, links))
	}
	return out
}

// Up brings a tunnel online. It is a no-op for tunnels the daemon does not own.
func (m *Manager) Up(ctx context.Context, t config.Tunnel) error {
	ctx, cancel := context.WithTimeout(ctx, ConnectTimeout)
	defer cancel()

	switch t.Kind {
	case config.KindNM:
		if _, err := run(ctx, "nmcli", "connection", "up", "id", t.Profile); err != nil {
			return fmt.Errorf("nmcli up %s: %w", t.Profile, err)
		}
		return nil

	case config.KindWGQuick:
		if _, err := run(ctx, "wg-quick", "up", t.Profile); err != nil {
			return fmt.Errorf("wg-quick up %s: %w", t.Profile, err)
		}
		return nil

	case config.KindAWGQuick:
		if _, err := run(ctx, "awg-quick", "up", t.Profile); err != nil {
			return fmt.Errorf("awg-quick up %s: %w", t.Profile, err)
		}
		return nil

	case config.KindManual:
		return fmt.Errorf("tunnel %q is manual; bring it up yourself", t.Name)
	}
	return fmt.Errorf("tunnel %q has unknown kind %q", t.Name, t.Kind)
}

// Down takes a tunnel offline.
func (m *Manager) Down(ctx context.Context, t config.Tunnel) error {
	ctx, cancel := context.WithTimeout(ctx, ConnectTimeout)
	defer cancel()

	switch t.Kind {
	case config.KindNM:
		if _, err := run(ctx, "nmcli", "connection", "down", "id", t.Profile); err != nil {
			return fmt.Errorf("nmcli down %s: %w", t.Profile, err)
		}
		return nil

	case config.KindWGQuick:
		if _, err := run(ctx, "wg-quick", "down", t.Profile); err != nil {
			return fmt.Errorf("wg-quick down %s: %w", t.Profile, err)
		}
		return nil

	case config.KindAWGQuick:
		if _, err := run(ctx, "awg-quick", "down", t.Profile); err != nil {
			return fmt.Errorf("awg-quick down %s: %w", t.Profile, err)
		}
		return nil

	case config.KindManual:
		return fmt.Errorf("tunnel %q is manual; take it down yourself", t.Name)
	}
	return fmt.Errorf("tunnel %q has unknown kind %q", t.Name, t.Kind)
}

// NMProfile describes a NetworkManager connection that could back a tunnel.
type NMProfile struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Device string `json:"device,omitempty"`
	Active bool   `json:"active"`
}

// ListNMProfiles enumerates VPN-capable NetworkManager profiles so the GUI can
// offer them when adding a tunnel.
func (m *Manager) ListNMProfiles(ctx context.Context) ([]NMProfile, error) {
	out, err := run(ctx, "nmcli", "-t", "-f", "NAME,TYPE,DEVICE,STATE", "connection", "show")
	if err != nil {
		return nil, fmt.Errorf("list nm profiles: %w", err)
	}

	var profiles []NMProfile
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := splitEscaped(line)
		if len(fields) < 4 {
			continue
		}
		kind := fields[1]
		if kind != "vpn" && kind != "wireguard" && kind != "tun" {
			continue
		}
		profiles = append(profiles, NMProfile{
			Name:   fields[0],
			Type:   kind,
			Device: fields[2],
			Active: fields[3] == "activated",
		})
	}
	return profiles, nil
}

// splitEscaped splits nmcli terse output, honouring its backslash escaping of colons.
func splitEscaped(line string) []string {
	var fields []string
	var cur strings.Builder
	for i := 0; i < len(line); i++ {
		switch {
		case line[i] == '\\' && i+1 < len(line):
			i++
			cur.WriteByte(line[i])
		case line[i] == ':':
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(line[i])
		}
	}
	fields = append(fields, cur.String())
	return fields
}
