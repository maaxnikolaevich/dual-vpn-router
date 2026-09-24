package config

import (
	"os"
	"path/filepath"
	"testing"
)

const legacyYAML = `dns:
    listen_addr: 127.0.0.1:53
    fallback:
        - 8.8.8.8
        - 8.8.4.4
    domains:
        - name: itlabs.io
          servers:
            - 10.0.16.1
            - 10.2.16.1
        - name: sdvor.com
          servers:
            - 10.0.16.1
            - 10.2.16.1
routing:
    corp_table_id: 200
    corp_networks:
        - 10.0.0.0/8
        - 172.16.0.0/12
vpns:
    - name: corporate
      interface: tun0
      auto_detect: true
      type: corporate
    - name: global
      interface: wg-test
      auto_detect: true
      type: global
`

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadMigratesLegacyConfig(t *testing.T) {
	cfg, err := Load(writeTemp(t, legacyYAML))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.Migrated {
		t.Error("expected Migrated to be true for a v1 file")
	}
	if cfg.Version != CurrentVersion {
		t.Errorf("version = %d, want %d", cfg.Version, CurrentVersion)
	}

	// listen_addr carried a port in v1; dnsmasq needs a bare address.
	if cfg.DNS.ListenAddr != "127.0.0.1" {
		t.Errorf("listen addr = %q, want 127.0.0.1", cfg.DNS.ListenAddr)
	}

	if len(cfg.Tunnels) != 2 {
		t.Fatalf("got %d tunnels, want 2", len(cfg.Tunnels))
	}
	corp, ok := cfg.Tunnel("corporate")
	if !ok {
		t.Fatal("corporate tunnel missing")
	}
	if corp.TableID != 200 {
		t.Errorf("corporate table_id = %d, want 200", corp.TableID)
	}
	if corp.Interface != "tun0" {
		t.Errorf("corporate interface = %q, want tun0", corp.Interface)
	}
	global, ok := cfg.Tunnel("global")
	if !ok {
		t.Fatal("global tunnel missing")
	}
	if global.TableID == corp.TableID {
		t.Errorf("global reused corporate table_id %d", global.TableID)
	}

	if len(cfg.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(cfg.Rules))
	}
	if cfg.Rules[0].Target != "corporate" {
		t.Errorf("rule target = %q, want corporate", cfg.Rules[0].Target)
	}
	if !cfg.Rules[0].Enabled {
		t.Error("migrated rule should be enabled")
	}

	if len(cfg.DNSRules) != 2 {
		t.Fatalf("got %d dns rules, want 2", len(cfg.DNSRules))
	}
	for _, d := range cfg.DNSRules {
		if d.Via != "corporate" {
			t.Errorf("dns rule %q via = %q, want corporate", d.Domain, d.Via)
		}
		if !d.Enabled {
			t.Errorf("dns rule %q should be enabled", d.Domain)
		}
	}
}

func TestRoundTripKeepsV2(t *testing.T) {
	cfg, err := Load(writeTemp(t, legacyYAML))
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "out.yaml")
	if err := Save(cfg, path); err != nil {
		t.Fatal(err)
	}

	again, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if again.Migrated {
		t.Error("a saved v2 file must not be treated as a migration")
	}
	if len(again.Tunnels) != len(cfg.Tunnels) || len(again.DNSRules) != len(cfg.DNSRules) {
		t.Error("round trip lost entries")
	}
}

func TestValidateRejectsBadConfigs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"duplicate table id", func(c *Config) { c.Tunnels[1].TableID = c.Tunnels[0].TableID }},
		{"reserved table id", func(c *Config) { c.Tunnels[0].TableID = 254 }},
		{"unknown rule target", func(c *Config) { c.Rules[0].Target = "nope" }},
		{"bad cidr", func(c *Config) { c.Rules[0].CIDRs = []string{"10.0.0.0/999"} }},
		{"duplicate tunnel name", func(c *Config) { c.Tunnels[1].Name = c.Tunnels[0].Name }},
		{"reserved tunnel name", func(c *Config) { c.Tunnels[0].Name = TargetDirect }},
		{"bad dns server", func(c *Config) { c.DNSRules[0].Servers = []string{"not-an-ip"} }},
		{"unknown dns via", func(c *Config) { c.DNSRules[0].Via = "nope" }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Rules[0].Target = cfg.Tunnels[0].Name
			cfg.DNSRules[0].Via = cfg.Tunnels[0].Name
			tc.mutate(cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected %s to be rejected", tc.name)
			}
		})
	}
}

func TestDefaultConfigIsValid(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
}
