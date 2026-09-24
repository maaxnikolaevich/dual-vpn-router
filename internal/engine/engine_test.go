package engine

import (
	"testing"

	"github.com/maks/dual-vpn-router/internal/config"
	"github.com/maks/dual-vpn-router/internal/routing"
	"github.com/maks/dual-vpn-router/internal/vpn"
)

// testEngine builds an engine with no system access; desired() and ruleEffect()
// are pure functions over config plus observed tunnel status.
func testEngine(cfg *config.Config, active bool) *Engine {
	return &Engine{cfg: cfg, active: active}
}

func baseConfig() *config.Config {
	return &config.Config{
		Version: config.CurrentVersion,
		DNS:     config.DNSConfig{ListenAddr: "127.0.0.1", Fallback: []string{"8.8.8.8"}},
		Tunnels: []config.Tunnel{
			{Name: "corp", Kind: config.KindNM, Profile: "ovpn1", TableID: 200},
			{Name: "wg", Kind: config.KindWGQuick, Profile: "wg0", TableID: 201},
		},
		Rules: []config.Rule{
			{ID: "corp-nets", Target: "corp", CIDRs: []string{"10.0.0.0/8"}, Enabled: true},
		},
		DNSRules: []config.DNSRule{
			{Domain: "itlabs.io", Servers: []string{"10.0.16.1"}, Via: "corp", Enabled: true},
		},
	}
}

func up(name string, iface string) vpn.Status {
	return vpn.Status{Name: name, Interface: iface, Present: true, Up: true}
}

func down(name string) vpn.Status {
	return vpn.Status{Name: name, Present: false, Up: false}
}

func hasRule(specs []routing.RuleSpec, want routing.RuleSpec) bool {
	for _, s := range specs {
		if s.TableID == want.TableID && s.To == want.To && s.Fwmark == want.Fwmark {
			return true
		}
	}
	return false
}

func TestDesiredInstallsRuleWhenTunnelIsUp(t *testing.T) {
	e := testEngine(baseConfig(), true)
	rules, marks, entries := e.desired(map[string]vpn.Status{
		"corp": up("corp", "tun0"),
		"wg":   down("wg"),
	})

	if !hasRule(rules, routing.RuleSpec{To: "10.0.0.0/8", TableID: 200}) {
		t.Errorf("corp network rule missing: %+v", rules)
	}
	// The resolver's own queries must be steered into the tunnel that reaches them.
	if !hasRule(rules, routing.RuleSpec{Fwmark: 200, TableID: 200}) {
		t.Errorf("dns fwmark rule missing: %+v", rules)
	}
	if len(marks) != 1 || marks[0].Server != "10.0.16.1" || marks[0].Mark != 200 {
		t.Errorf("dns marks = %+v, want one mark 200 for 10.0.16.1", marks)
	}
	if len(entries) != 1 || entries[0].Domain != "itlabs.io" {
		t.Errorf("dns entries = %+v", entries)
	}
}

func TestDesiredSkipsRuleWhenTunnelIsDown(t *testing.T) {
	// Failing open: without the tunnel the rule is withdrawn so traffic still flows.
	e := testEngine(baseConfig(), true)
	rules, _, _ := e.desired(map[string]vpn.Status{"corp": down("corp")})

	if hasRule(rules, routing.RuleSpec{To: "10.0.0.0/8", TableID: 200}) {
		t.Errorf("rule should not be installed while its tunnel is down: %+v", rules)
	}
}

func TestDesiredKeepsFailClosedRuleWhenTunnelIsDown(t *testing.T) {
	// Failing closed: the rule stays so traffic hits the blackholed table
	// instead of leaking out the default route.
	cfg := baseConfig()
	cfg.Rules[0].FailClosed = true

	e := testEngine(cfg, true)
	rules, _, _ := e.desired(map[string]vpn.Status{"corp": down("corp")})

	if !hasRule(rules, routing.RuleSpec{To: "10.0.0.0/8", TableID: 200}) {
		t.Errorf("fail-closed rule must stay installed to prevent a leak: %+v", rules)
	}
}

func TestDesiredIgnoresDisabledEntries(t *testing.T) {
	cfg := baseConfig()
	cfg.Rules[0].Enabled = false
	cfg.DNSRules[0].Enabled = false

	e := testEngine(cfg, true)
	rules, marks, entries := e.desired(map[string]vpn.Status{"corp": up("corp", "tun0")})

	if len(rules) != 0 {
		t.Errorf("disabled rule produced %+v", rules)
	}
	if len(marks) != 0 {
		t.Errorf("disabled dns rule produced marks %+v", marks)
	}
	if len(entries) != 0 {
		t.Errorf("disabled dns rule produced entries %+v", entries)
	}
}

func TestDesiredRoutesDirectThroughMainTable(t *testing.T) {
	cfg := baseConfig()
	cfg.Rules = append(cfg.Rules, config.Rule{
		ID: "bypass", Target: config.TargetDirect,
		CIDRs: []string{"192.168.1.0/24"}, Enabled: true,
	})

	e := testEngine(cfg, true)
	rules, _, _ := e.desired(map[string]vpn.Status{"corp": up("corp", "tun0")})

	if !hasRule(rules, routing.RuleSpec{To: "192.168.1.0/24", TableID: mainTableID}) {
		t.Errorf("direct rule should use the main table: %+v", rules)
	}
}

func TestDesiredConfiguresDNSEvenWhenViaTunnelIsDown(t *testing.T) {
	// dnsmasq should still know the override; only the routing mark is skipped,
	// otherwise the domain would silently resolve through the wrong upstream.
	e := testEngine(baseConfig(), true)
	_, marks, entries := e.desired(map[string]vpn.Status{"corp": down("corp")})

	if len(entries) != 1 {
		t.Errorf("dns entry should persist while the tunnel is down: %+v", entries)
	}
	if len(marks) != 0 {
		t.Errorf("no marks should be installed for a down tunnel: %+v", marks)
	}
}

func TestRuleEffectExplainsWhyARuleIsInactive(t *testing.T) {
	cfg := baseConfig()

	tests := []struct {
		name        string
		active      bool
		enabled     bool
		failClosed  bool
		status      vpn.Status
		wantApplied bool
		wantReason  string
	}{
		{"stopped router", false, true, false, up("corp", "tun0"), false, "router stopped"},
		{"disabled rule", true, false, false, up("corp", "tun0"), false, "disabled"},
		{"tunnel down", true, true, false, down("corp"), false, "tunnel corp is down"},
		{"fail closed", true, true, true, down("corp"), true, "tunnel down, traffic blackholed"},
		{"all good", true, true, false, up("corp", "tun0"), true, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := testEngine(cfg, tc.active)
			r := config.Rule{ID: "x", Target: "corp", Enabled: tc.enabled, FailClosed: tc.failClosed}

			applied, reason := e.ruleEffect(r, map[string]vpn.Status{"corp": tc.status})
			if applied != tc.wantApplied {
				t.Errorf("applied = %v, want %v", applied, tc.wantApplied)
			}
			if reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", reason, tc.wantReason)
			}
		})
	}
}

func TestTunnelHasFailClosedOnlyCountsEnabledRules(t *testing.T) {
	cfg := baseConfig()
	cfg.Rules[0].FailClosed = true
	cfg.Rules[0].Enabled = false

	e := testEngine(cfg, true)
	// A disabled fail-closed rule must not blackhole the table, otherwise
	// turning a rule off would break traffic instead of restoring it.
	if e.tunnelHasFailClosed("corp") {
		t.Error("disabled fail-closed rule should not blackhole the table")
	}

	cfg.Rules[0].Enabled = true
	if !e.tunnelHasFailClosed("corp") {
		t.Error("enabled fail-closed rule should blackhole the table")
	}
}

func TestFreeTableIDSkipsUsed(t *testing.T) {
	e := testEngine(baseConfig(), false)
	got := e.freeTableID()
	if got == 200 || got == 201 {
		t.Errorf("freeTableID returned in-use id %d", got)
	}
	if got < 200 || got > 252 {
		t.Errorf("freeTableID returned %d, outside the usable range", got)
	}
}
