package vpn

import (
	"context"
	"testing"

	"github.com/maks/dual-vpn-router/internal/config"
)

func TestParseLinksReadsUpState(t *testing.T) {
	// Trimmed real `ip -j addr show` output: a carrier-less tun (operstate
	// UNKNOWN but flagged UP) and an administratively down interface.
	data := []byte(`[
	 {"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"operstate":"UNKNOWN",
	  "addr_info":[{"family":"inet","local":"127.0.0.1"}]},
	 {"ifname":"outline-tun0","flags":["POINTOPOINT","MULTICAST","NOARP","UP","LOWER_UP"],
	  "operstate":"UNKNOWN","addr_info":[{"family":"inet","local":"10.0.85.1"}]},
	 {"ifname":"wg0","flags":["POINTOPOINT","NOARP"],"operstate":"DOWN","addr_info":[]}
	]`)

	links, err := parseLinks(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(links) != 3 {
		t.Fatalf("got %d links, want 3", len(links))
	}

	// A point-to-point tunnel reports UNKNOWN operstate even when usable.
	if !links["outline-tun0"].up() {
		t.Error("outline-tun0 should be considered up")
	}
	if links["wg0"].up() {
		t.Error("wg0 is DOWN and must not be considered up")
	}
	if got := links["outline-tun0"].AddrInfo[0].Local; got != "10.0.85.1" {
		t.Errorf("address = %q, want 10.0.85.1", got)
	}
}

func TestParseGateway(t *testing.T) {
	tests := []struct {
		name string
		data string
		want string
	}{
		{
			name: "classic default via gateway",
			data: `[{"dst":"default","gateway":"10.8.0.1","dev":"tun0"}]`,
			want: "10.8.0.1",
		},
		{
			// WireGuard installs a gateway-less default; callers must route by device.
			name: "point to point default",
			data: `[{"dst":"default","dev":"wg0"}]`,
			want: "",
		},
		{
			name: "link route only",
			data: `[{"dst":"10.0.85.2","scope":"link","prefsrc":"10.0.85.1"}]`,
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseGateway([]byte(tc.data))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got != tc.want {
				t.Errorf("gateway = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFirstTunnelLikeIsDeterministic(t *testing.T) {
	links := map[string]Link{
		"wlp0s20f3":    {IfName: "wlp0s20f3", Flags: []string{"UP"}, OperState: "UP"},
		"wg0":          {IfName: "wg0", Flags: []string{"UP"}, OperState: "UNKNOWN"},
		"tun0":         {IfName: "tun0", Flags: []string{"UP"}, OperState: "UNKNOWN"},
		"outline-tun0": {IfName: "outline-tun0", Flags: []string{"UP"}, OperState: "UNKNOWN"},
		"docker0":      {IfName: "docker0", Flags: []string{"UP"}, OperState: "UP"},
	}

	// Repeated calls must agree despite random map iteration order.
	first := firstTunnelLike(links)
	for i := 0; i < 50; i++ {
		if got := firstTunnelLike(links); got != first {
			t.Fatalf("nondeterministic: got %q then %q", first, got)
		}
	}
	if first != "tun0" {
		t.Errorf("picked %q, want tun0 (first sorted tunnel-like name)", first)
	}
}

func TestFirstTunnelLikeSkipsDownInterfaces(t *testing.T) {
	links := map[string]Link{
		"tun0": {IfName: "tun0", Flags: []string{"POINTOPOINT"}, OperState: "DOWN"},
		"wg0":  {IfName: "wg0", Flags: []string{"UP"}, OperState: "UNKNOWN"},
	}
	if got := firstTunnelLike(links); got != "wg0" {
		t.Errorf("picked %q, want wg0", got)
	}
}

// A tunnel whose kind names its profile must never borrow an unrelated
// interface: doing so pointed one tunnel's routes at somebody else's VPN.
func TestResolveInterfaceNeverGuessesForProfiledKinds(t *testing.T) {
	links := map[string]Link{
		"wg-test": {IfName: "wg-test", Flags: []string{"UP"}, OperState: "UNKNOWN"},
	}
	m := New()

	nm := config.Tunnel{
		Name: "ovpn1", Kind: config.KindNM,
		// A profile nmcli cannot resolve, standing in for one that is down.
		Profile: "dual-vpn-test-no-such-profile", AutoDetect: true,
	}
	if got := m.ResolveInterface(context.Background(), nm, links); got != "" {
		t.Errorf("nm tunnel resolved to %q, want empty rather than an unrelated tunnel", got)
	}

	wg := config.Tunnel{Name: "global", Kind: config.KindWGQuick, Profile: "wg0", AutoDetect: true}
	if got := m.ResolveInterface(context.Background(), wg, links); got != "wg0" {
		t.Errorf("wg-quick tunnel resolved to %q, want wg0", got)
	}

	awg := config.Tunnel{Name: "amnezia", Kind: config.KindAWGQuick, Profile: "wg-test", AutoDetect: true}
	if got := m.ResolveInterface(context.Background(), awg, links); got != "wg-test" {
		t.Errorf("awg-quick tunnel resolved to %q, want wg-test", got)
	}
}

func TestResolveInterfaceAutodetectsOnlyForManual(t *testing.T) {
	links := map[string]Link{
		"wg-test": {IfName: "wg-test", Flags: []string{"UP"}, OperState: "UNKNOWN"},
	}
	m := New()

	manual := config.Tunnel{Name: "observed", Kind: config.KindManual, AutoDetect: true}
	if got := m.ResolveInterface(context.Background(), manual, links); got != "wg-test" {
		t.Errorf("manual tunnel resolved to %q, want wg-test", got)
	}

	pinned := config.Tunnel{Name: "pinned", Kind: config.KindManual, Interface: "tun9", AutoDetect: true}
	if got := m.ResolveInterface(context.Background(), pinned, links); got != "tun9" {
		t.Errorf("explicit interface resolved to %q, want tun9", got)
	}
}

func addrs(ips ...string) []Addr {
	out := make([]Addr, 0, len(ips))
	for _, ip := range ips {
		out = append(out, Addr{Family: "inet", Local: ip})
	}
	return out
}

// Real `nmcli connection show` output for an active OpenVPN profile. Note that
// GENERAL.DEVICES is the wifi card the tunnel runs over, not the tunnel.
const nmVPNShow = `GENERAL.VPN:yes
GENERAL.DEVICES:wlp0s20f3
GENERAL.IP-IFACE:wlp0s20f3
GENERAL.STATE:activated
IP4.ADDRESS[1]:10.2.200.30/21
IP4.GATEWAY:10.2.200.1`

func TestNMDeviceResolvesVPNByAddress(t *testing.T) {
	links := map[string]Link{
		"wlp0s20f3": {IfName: "wlp0s20f3", AddrInfo: addrs("192.168.1.42")},
		"tun0":      {IfName: "tun0", AddrInfo: addrs("10.2.200.30")},
	}
	if got := nmDeviceFrom(nmVPNShow, links); got != "tun0" {
		t.Errorf("resolved %q, want tun0; wlp0s20f3 would route the tunnel out the local link", got)
	}
}

func TestNMDeviceReportsNothingWhenVPNAddressIsGone(t *testing.T) {
	// The profile is configured but not connected, so no link holds its address.
	links := map[string]Link{
		"wlp0s20f3": {IfName: "wlp0s20f3", AddrInfo: addrs("192.168.1.42")},
	}
	if got := nmDeviceFrom(nmVPNShow, links); got != "" {
		t.Errorf("resolved %q, want empty so the tunnel reads as down", got)
	}
}

func TestNMDeviceTrustsDevicesForNonVPNProfiles(t *testing.T) {
	// A tun-type profile such as Outline really does own its device.
	out := "GENERAL.VPN:no\nGENERAL.DEVICES:outline-tun0\n"
	if got := nmDeviceFrom(out, nil); got != "outline-tun0" {
		t.Errorf("resolved %q, want outline-tun0", got)
	}
}

func TestTunnelLikeMatchesSuffixedNames(t *testing.T) {
	// Real names seen on the host: Outline prefixes its device, AmneziaWG does not.
	for _, name := range []string{"tun0", "wg0", "wg-test", "outline-tun0", "ppp0"} {
		if !tunnelLike(name) {
			t.Errorf("%q should count as tunnel-like", name)
		}
	}
	for _, name := range []string{"lo", "eth0", "wlp0s20f3", "docker0", "virbr0"} {
		if tunnelLike(name) {
			t.Errorf("%q should not count as tunnel-like", name)
		}
	}
}

func TestSplitEscapedHandlesColonsInNames(t *testing.T) {
	// nmcli terse output escapes literal colons inside connection names.
	got := splitEscaped(`My\:VPN:vpn:tun0:activated`)
	want := []string{"My:VPN", "vpn", "tun0", "activated"}

	if len(got) != len(want) {
		t.Fatalf("got %d fields %q, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("field %d = %q, want %q", i, got[i], want[i])
		}
	}
}
