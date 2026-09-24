package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// CurrentVersion is the schema version this build reads and writes.
const CurrentVersion = 2

// TargetDirect routes matching traffic through the main table, bypassing every tunnel.
const TargetDirect = "direct"

// TunnelKind selects how a tunnel is brought up and torn down.
type TunnelKind string

const (
	// KindNM drives a NetworkManager connection profile via nmcli.
	KindNM TunnelKind = "nm"
	// KindWGQuick drives /etc/wireguard/<profile>.conf via wg-quick.
	KindWGQuick TunnelKind = "wg-quick"
	// KindAWGQuick drives /etc/amnezia/amneziawg/<profile>.conf via awg-quick,
	// the AmneziaWG fork of wg-quick.
	KindAWGQuick TunnelKind = "awg-quick"
	// KindManual never starts or stops the tunnel, it is only observed.
	KindManual TunnelKind = "manual"
)

// AmneziaDir is where awg-quick looks up a bare profile name.
const AmneziaDir = "/etc/amnezia/amneziawg"

type Config struct {
	Version  int       `yaml:"version"`
	DNS      DNSConfig `yaml:"dns"`
	Tunnels  []Tunnel  `yaml:"tunnels"`
	Rules    []Rule    `yaml:"rules"`
	DNSRules []DNSRule `yaml:"dns_rules"`

	// Migrated reports that Load upgraded a v1 file in memory; it has not been persisted yet.
	Migrated bool `yaml:"-"`
}

type DNSConfig struct {
	ListenAddr string   `yaml:"listen_addr"`
	Fallback   []string `yaml:"fallback"`
}

type Tunnel struct {
	Name       string     `yaml:"name"`
	Kind       TunnelKind `yaml:"kind"`
	Profile    string     `yaml:"profile,omitempty"`
	Interface  string     `yaml:"interface,omitempty"`
	TableID    int        `yaml:"table_id"`
	AutoDetect bool       `yaml:"auto_detect"`
}

// TableName is the /etc/iproute2/rt_tables alias owned by this tunnel.
func (t Tunnel) TableName() string { return "dvpn_" + t.Name }

// Mark is the fwmark used to steer DNS traffic into this tunnel's table.
func (t Tunnel) Mark() int { return t.TableID }

type Rule struct {
	ID      string   `yaml:"id"`
	Target  string   `yaml:"target"`
	CIDRs   []string `yaml:"cidrs"`
	Enabled bool     `yaml:"enabled"`
	Comment string   `yaml:"comment,omitempty"`

	// FailClosed drops matching traffic while the target tunnel is down instead
	// of letting it fall through to the default route and leave the tunnel.
	FailClosed bool `yaml:"fail_closed,omitempty"`
}

type DNSRule struct {
	Domain  string   `yaml:"domain"`
	Servers []string `yaml:"servers"`
	Via     string   `yaml:"via"`
	Enabled bool     `yaml:"enabled"`
}

func (c *Config) Tunnel(name string) (*Tunnel, bool) {
	for i := range c.Tunnels {
		if c.Tunnels[i].Name == name {
			return &c.Tunnels[i], true
		}
	}
	return nil, false
}

func (c *Config) Rule(id string) (*Rule, bool) {
	for i := range c.Rules {
		if c.Rules[i].ID == id {
			return &c.Rules[i], true
		}
	}
	return nil, false
}

func (c *Config) DNSRule(domain string) (*DNSRule, bool) {
	for i := range c.DNSRules {
		if c.DNSRules[i].Domain == domain {
			return &c.DNSRules[i], true
		}
	}
	return nil, false
}

// Clone deep-copies the config so a failed edit can be rolled back wholesale.
// It round-trips through YAML, which is what Save uses, so anything that
// survives a clone also survives a write.
func (c *Config) Clone() *Config {
	data, err := yaml.Marshal(c)
	if err != nil {
		// Config contains only plain data; marshalling it cannot fail.
		panic(fmt.Sprintf("clone config: %v", err))
	}
	var out Config
	if err := yaml.Unmarshal(data, &out); err != nil {
		panic(fmt.Sprintf("clone config: %v", err))
	}
	return &out
}

func DefaultConfig() *Config {
	return &Config{
		Version: CurrentVersion,
		DNS: DNSConfig{
			ListenAddr: "127.0.0.1",
			Fallback:   []string{"8.8.8.8", "8.8.4.4"},
		},
		Tunnels: []Tunnel{
			{Name: "corp", Kind: KindNM, Profile: "corporate-vpn", TableID: 200, AutoDetect: true},
			{Name: "global", Kind: KindWGQuick, Profile: "wg0", TableID: 201, AutoDetect: true},
		},
		Rules: []Rule{
			{
				ID:      "corp-networks",
				Target:  "corp",
				CIDRs:   []string{"10.0.0.0/8", "172.16.0.0/12"},
				Enabled: true,
				Comment: "Private ranges reachable through the corporate tunnel",
			},
		},
		DNSRules: []DNSRule{
			{Domain: "corporate.example.com", Servers: []string{"192.168.1.1"}, Via: "corp", Enabled: true},
		},
	}
}

// Validate rejects configurations that would produce a broken or dangerous routing state.
func (c *Config) Validate() error {
	seenName := map[string]bool{}
	seenTable := map[int]string{}

	for _, t := range c.Tunnels {
		if t.Name == "" {
			return fmt.Errorf("tunnel has an empty name")
		}
		if t.Name == TargetDirect {
			return fmt.Errorf("tunnel name %q is reserved", TargetDirect)
		}
		if seenName[t.Name] {
			return fmt.Errorf("duplicate tunnel name %q", t.Name)
		}
		seenName[t.Name] = true

		switch t.Kind {
		case KindNM, KindWGQuick, KindAWGQuick:
			if t.Profile == "" {
				return fmt.Errorf("tunnel %q of kind %q needs a profile", t.Name, t.Kind)
			}
		case KindManual:
			if t.Interface == "" && !t.AutoDetect {
				return fmt.Errorf("manual tunnel %q needs an interface or auto_detect", t.Name)
			}
		default:
			return fmt.Errorf("tunnel %q has unknown kind %q", t.Name, t.Kind)
		}

		// 253-255 are local/main/default; colliding with them breaks the host's routing.
		if t.TableID < 1 || t.TableID > 252 {
			return fmt.Errorf("tunnel %q table_id %d out of range 1-252", t.Name, t.TableID)
		}
		if other, dup := seenTable[t.TableID]; dup {
			return fmt.Errorf("tunnels %q and %q share table_id %d", other, t.Name, t.TableID)
		}
		seenTable[t.TableID] = t.Name
	}

	seenRule := map[string]bool{}
	for _, r := range c.Rules {
		if r.ID == "" {
			return fmt.Errorf("routing rule has an empty id")
		}
		if seenRule[r.ID] {
			return fmt.Errorf("duplicate routing rule id %q", r.ID)
		}
		seenRule[r.ID] = true

		if r.Target != TargetDirect && !seenName[r.Target] {
			return fmt.Errorf("routing rule %q targets unknown tunnel %q", r.ID, r.Target)
		}
		if len(r.CIDRs) == 0 {
			return fmt.Errorf("routing rule %q has no cidrs", r.ID)
		}
		for _, cidr := range r.CIDRs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("routing rule %q has invalid cidr %q", r.ID, cidr)
			}
		}
	}

	seenDomain := map[string]bool{}
	for _, d := range c.DNSRules {
		if d.Domain == "" {
			return fmt.Errorf("dns rule has an empty domain")
		}
		if seenDomain[d.Domain] {
			return fmt.Errorf("duplicate dns rule for %q", d.Domain)
		}
		seenDomain[d.Domain] = true

		if len(d.Servers) == 0 {
			return fmt.Errorf("dns rule %q has no servers", d.Domain)
		}
		for _, s := range d.Servers {
			if net.ParseIP(s) == nil {
				return fmt.Errorf("dns rule %q has invalid server ip %q", d.Domain, s)
			}
		}
		if d.Via != "" && d.Via != TargetDirect && !seenName[d.Via] {
			return fmt.Errorf("dns rule %q routes via unknown tunnel %q", d.Domain, d.Via)
		}
	}

	for _, s := range c.DNS.Fallback {
		if net.ParseIP(s) == nil {
			return fmt.Errorf("invalid fallback dns server %q", s)
		}
	}
	return nil
}

// Load reads a config file, upgrading v1 files to the current schema in memory.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var probe struct {
		Version int `yaml:"version"`
	}
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	var cfg *Config
	if probe.Version >= 2 {
		cfg = &Config{}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	} else {
		var legacy v1Config
		if err := yaml.Unmarshal(data, &legacy); err != nil {
			return nil, fmt.Errorf("parse legacy %s: %w", path, err)
		}
		cfg = legacy.migrate()
		cfg.Migrated = true
	}

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	c.Version = CurrentVersion
	if c.DNS.ListenAddr == "" {
		c.DNS.ListenAddr = "127.0.0.1"
	}
	// The legacy schema stored host:port here, but dnsmasq wants a bare address.
	if host, _, err := net.SplitHostPort(c.DNS.ListenAddr); err == nil {
		c.DNS.ListenAddr = host
	}
	if len(c.DNS.Fallback) == 0 {
		c.DNS.Fallback = []string{"8.8.8.8", "8.8.4.4"}
	}
	for i := range c.Tunnels {
		if c.Tunnels[i].Kind == "" {
			c.Tunnels[i].Kind = KindManual
		}
		if c.Tunnels[i].TableID == 0 {
			c.Tunnels[i].TableID = 200 + i
		}
	}
}

// Save writes the config atomically so a crash mid-write cannot truncate it.
func Save(cfg *Config, path string) error {
	cfg.Version = CurrentVersion
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".config-*.yaml")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// v1Config is the pre-v2 schema, kept only so existing installs migrate cleanly.
type v1Config struct {
	DNS struct {
		ListenAddr string   `yaml:"listen_addr"`
		Fallback   []string `yaml:"fallback"`
		Domains    []struct {
			Name    string   `yaml:"name"`
			Servers []string `yaml:"servers"`
		} `yaml:"domains"`
	} `yaml:"dns"`
	Routing struct {
		CorpTableID  int      `yaml:"corp_table_id"`
		CorpNetworks []string `yaml:"corp_networks"`
	} `yaml:"routing"`
	VPNs []struct {
		Name       string `yaml:"name"`
		Interface  string `yaml:"interface"`
		AutoDetect bool   `yaml:"auto_detect"`
		Type       string `yaml:"type"`
	} `yaml:"vpns"`
}

func (l v1Config) migrate() *Config {
	cfg := &Config{
		Version: CurrentVersion,
		DNS: DNSConfig{
			ListenAddr: l.DNS.ListenAddr,
			Fallback:   l.DNS.Fallback,
		},
	}

	corpTable := l.Routing.CorpTableID
	if corpTable == 0 {
		corpTable = 200
	}

	// v1 only ever had a corporate tunnel and a global one, distinguished by Type.
	corpName := "corp"
	nextTable := corpTable
	for _, v := range l.VPNs {
		name := v.Name
		if name == "" {
			name = v.Interface
		}
		var table int
		if v.Type == "corporate" {
			table = corpTable
			corpName = name
		} else {
			nextTable++
			if nextTable == corpTable {
				nextTable++
			}
			table = nextTable
		}
		cfg.Tunnels = append(cfg.Tunnels, Tunnel{
			Name:       name,
			Kind:       KindManual,
			Interface:  v.Interface,
			TableID:    table,
			AutoDetect: v.AutoDetect,
		})
	}

	if len(l.Routing.CorpNetworks) > 0 {
		cfg.Rules = append(cfg.Rules, Rule{
			ID:      "corp-networks",
			Target:  corpName,
			CIDRs:   l.Routing.CorpNetworks,
			Enabled: true,
			Comment: "Migrated from routing.corp_networks",
		})
	}

	for _, d := range l.DNS.Domains {
		cfg.DNSRules = append(cfg.DNSRules, DNSRule{
			Domain:  strings.TrimSpace(d.Name),
			Servers: d.Servers,
			Via:     corpName,
			Enabled: true,
		})
	}

	return cfg
}
