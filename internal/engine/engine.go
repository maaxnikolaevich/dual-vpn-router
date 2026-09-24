// Package engine owns the live state of the router. It converts the declarative
// config into concrete routing, DNS and tunnel actions, and is the only place
// that mutates system state.
package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/maks/dual-vpn-router/internal/config"
	"github.com/maks/dual-vpn-router/internal/dns"
	"github.com/maks/dual-vpn-router/internal/routing"
	"github.com/maks/dual-vpn-router/internal/vpn"
)

// mainTableID is the kernel's main routing table, used by rules targeting "direct".
const mainTableID = 254

const activeMarkerPath = "/var/lib/dual-vpn/active"

// TunnelView is a tunnel's configuration joined with its observed status.
type TunnelView struct {
	Name      string            `json:"name"`
	Kind      config.TunnelKind `json:"kind"`
	Profile   string            `json:"profile,omitempty"`
	TableID   int               `json:"table_id"`
	Interface string            `json:"interface,omitempty"`
	Present   bool              `json:"present"`
	Up        bool              `json:"up"`
	Gateway   string            `json:"gateway,omitempty"`
	Addresses []string          `json:"addresses,omitempty"`
	Managed   bool              `json:"managed"`
	Detail    string            `json:"detail,omitempty"`
}

// RuleView is a routing rule plus whether it is actually in force.
type RuleView struct {
	ID         string   `json:"id"`
	Target     string   `json:"target"`
	CIDRs      []string `json:"cidrs"`
	Enabled    bool     `json:"enabled"`
	FailClosed bool     `json:"fail_closed"`
	Comment    string   `json:"comment,omitempty"`
	Applied    bool     `json:"applied"`
	Reason     string   `json:"reason,omitempty"`
}

// DNSRuleView is a DNS override plus whether it is actually in force.
type DNSRuleView struct {
	Domain  string   `json:"domain"`
	Servers []string `json:"servers"`
	Via     string   `json:"via,omitempty"`
	Enabled bool     `json:"enabled"`
	Applied bool     `json:"applied"`
	Reason  string   `json:"reason,omitempty"`
}

// State is the complete snapshot the GUI renders.
type State struct {
	Active     bool          `json:"active"`
	ListenAddr string        `json:"listen_addr"`
	Fallback   []string      `json:"fallback"`
	Tunnels    []TunnelView  `json:"tunnels"`
	Rules      []RuleView    `json:"rules"`
	DNSRules   []DNSRuleView `json:"dns_rules"`
	LastError  string        `json:"last_error,omitempty"`
}

type Engine struct {
	mu      sync.Mutex
	cfgPath string
	cfg     *config.Config

	vpn *vpn.Manager
	rt  *routing.Manager
	dns *dns.Manager

	active    bool
	lastError string
}

func New(cfgPath string) (*Engine, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}

	e := &Engine{
		cfgPath: cfgPath,
		cfg:     cfg,
		vpn:     vpn.New(),
		rt:      routing.New(),
		dns:     dns.New(),
	}
	// A v1 file was upgraded in memory; persist it so the GUI edits the new schema.
	if cfg.Migrated {
		if err := config.Save(cfg, cfgPath); err != nil {
			return nil, fmt.Errorf("persist migrated config: %w", err)
		}
		cfg.Migrated = false
	}

	if _, err := os.Stat(activeMarkerPath); err == nil {
		e.active = true
	}
	return e, nil
}

// Config returns a copy-safe handle for callers that only read.
func (e *Engine) Config() *config.Config {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cfg
}

func (e *Engine) setActive(active bool) error {
	e.active = active
	if !active {
		if err := os.Remove(activeMarkerPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(activeMarkerPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(activeMarkerPath, []byte("1\n"), 0o644)
}

func (e *Engine) save() error { return config.Save(e.cfg, e.cfgPath) }

// State reports configuration joined with live observation.
func (e *Engine) State(ctx context.Context) State {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stateLocked(ctx)
}

func (e *Engine) stateLocked(ctx context.Context) State {
	statuses := e.vpn.StatusAll(ctx, e.cfg.Tunnels)
	byName := make(map[string]vpn.Status, len(statuses))
	for _, s := range statuses {
		byName[s.Name] = s
	}

	st := State{
		Active:     e.active,
		ListenAddr: e.cfg.DNS.ListenAddr,
		Fallback:   e.cfg.DNS.Fallback,
		LastError:  e.lastError,
	}

	for _, t := range e.cfg.Tunnels {
		s := byName[t.Name]
		st.Tunnels = append(st.Tunnels, TunnelView{
			Name:      t.Name,
			Kind:      t.Kind,
			Profile:   t.Profile,
			TableID:   t.TableID,
			Interface: s.Interface,
			Present:   s.Present,
			Up:        s.Up,
			Gateway:   s.Gateway,
			Addresses: s.Addresses,
			Managed:   t.Kind != config.KindManual,
			Detail:    s.Detail,
		})
	}

	for _, r := range e.cfg.Rules {
		v := RuleView{
			ID:         r.ID,
			Target:     r.Target,
			CIDRs:      r.CIDRs,
			Enabled:    r.Enabled,
			FailClosed: r.FailClosed,
			Comment:    r.Comment,
		}
		v.Applied, v.Reason = e.ruleEffect(r, byName)
		st.Rules = append(st.Rules, v)
	}

	for _, d := range e.cfg.DNSRules {
		v := DNSRuleView{
			Domain:  d.Domain,
			Servers: d.Servers,
			Via:     d.Via,
			Enabled: d.Enabled,
		}
		switch {
		case !e.active:
			v.Reason = "router stopped"
		case !d.Enabled:
			v.Reason = "disabled"
		default:
			v.Applied = true
		}
		st.DNSRules = append(st.DNSRules, v)
	}

	return st
}

// ruleEffect explains whether a rule is currently installed, and if not, why.
func (e *Engine) ruleEffect(r config.Rule, byName map[string]vpn.Status) (bool, string) {
	if !e.active {
		return false, "router stopped"
	}
	if !r.Enabled {
		return false, "disabled"
	}
	if r.Target == config.TargetDirect {
		return true, ""
	}
	s, ok := byName[r.Target]
	if !ok {
		return false, "unknown tunnel " + r.Target
	}
	if !s.Routable() {
		if r.FailClosed {
			return true, "tunnel down, traffic blackholed"
		}
		return false, "tunnel " + r.Target + " is down"
	}
	return true, ""
}

// desired computes the routing rules, DNS marks and DNS entries implied by the
// current config and tunnel observations.
func (e *Engine) desired(byName map[string]vpn.Status) ([]routing.RuleSpec, []routing.MarkSpec, []dns.Entry) {
	var rules []routing.RuleSpec
	var marks []routing.MarkSpec
	var entries []dns.Entry

	tableOf := func(target string) (int, bool, bool) {
		if target == config.TargetDirect {
			return mainTableID, true, true
		}
		t, ok := e.cfg.Tunnel(target)
		if !ok {
			return 0, false, false
		}
		s := byName[target]
		return t.TableID, s.Routable(), true
	}

	for _, r := range e.cfg.Rules {
		if !r.Enabled {
			continue
		}
		table, routable, known := tableOf(r.Target)
		if !known {
			continue
		}
		// A rule whose tunnel is down is only installed when it is fail-closed,
		// where the point is to drop traffic rather than let it leak.
		if !routable && !r.FailClosed {
			continue
		}
		for _, cidr := range r.CIDRs {
			rules = append(rules, routing.RuleSpec{To: cidr, TableID: table})
		}
	}

	for _, d := range e.cfg.DNSRules {
		if !d.Enabled {
			continue
		}
		entries = append(entries, dns.Entry{Domain: d.Domain, Servers: d.Servers})

		if d.Via == "" || d.Via == config.TargetDirect {
			continue
		}
		t, ok := e.cfg.Tunnel(d.Via)
		if !ok || !byName[d.Via].Routable() {
			continue
		}
		// Steer the resolver's own queries into the tunnel that can reach them.
		for _, server := range d.Servers {
			marks = append(marks, routing.MarkSpec{Server: server, Mark: t.Mark()})
			rules = append(rules, routing.RuleSpec{Fwmark: t.Mark(), TableID: t.TableID})
		}
	}

	return rules, marks, entries
}

// Apply converges the system on the current config. Safe to call repeatedly.
func (e *Engine) Apply(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.applyLocked(ctx)
}

func (e *Engine) applyLocked(ctx context.Context) error {
	if !e.active {
		return nil
	}

	statuses := e.vpn.StatusAll(ctx, e.cfg.Tunnels)
	byName := make(map[string]vpn.Status, len(statuses))
	for _, s := range statuses {
		byName[s.Name] = s
	}

	var errs []string

	// Point each tunnel's table at its interface before any rule can select it.
	for _, t := range e.cfg.Tunnels {
		s := byName[t.Name]
		if s.Routable() {
			if err := e.rt.SetTableDefault(ctx, t.TableID, s.Interface, s.Gateway); err != nil {
				errs = append(errs, err.Error())
			}
			continue
		}
		// The tunnel is down. If anything fail-closed points at it, the table
		// must drop traffic instead of falling through to main.
		if e.tunnelHasFailClosed(t.Name) {
			if err := e.rt.SetTableBlackhole(ctx, t.TableID); err != nil {
				errs = append(errs, err.Error())
			}
		} else if err := e.rt.FlushTable(ctx, t.TableID); err != nil {
			errs = append(errs, err.Error())
		}
	}

	rules, marks, entries := e.desired(byName)

	if err := e.rt.SyncDNSMarks(ctx, marks); err != nil {
		errs = append(errs, err.Error())
	}
	if err := e.rt.ReconcileRules(ctx, rules); err != nil {
		errs = append(errs, err.Error())
	}
	if err := e.dns.Apply(ctx, e.cfg.DNS.ListenAddr, entries, e.cfg.DNS.Fallback); err != nil {
		errs = append(errs, err.Error())
	}

	if len(errs) > 0 {
		e.lastError = strings.Join(errs, "; ")
		return fmt.Errorf("apply: %s", e.lastError)
	}
	e.lastError = ""
	return nil
}

func (e *Engine) tunnelHasFailClosed(name string) bool {
	for _, r := range e.cfg.Rules {
		if r.Enabled && r.FailClosed && r.Target == name {
			return true
		}
	}
	return false
}

// Start enables the router and applies the configuration.
func (e *Engine) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.setActive(true); err != nil {
		return err
	}
	return e.applyLocked(ctx)
}

// Stop tears down everything this tool installed, leaving tunnels themselves alone.
func (e *Engine) Stop(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stopLocked(ctx)
}

func (e *Engine) stopLocked(ctx context.Context) error {
	var errs []string

	ids := make([]int, 0, len(e.cfg.Tunnels))
	for _, t := range e.cfg.Tunnels {
		ids = append(ids, t.TableID)
	}
	if err := e.rt.Cleanup(ctx, ids); err != nil {
		errs = append(errs, err.Error())
	}
	if err := e.dns.Cleanup(ctx); err != nil {
		errs = append(errs, err.Error())
	}
	if err := e.setActive(false); err != nil {
		errs = append(errs, err.Error())
	}

	if len(errs) > 0 {
		e.lastError = strings.Join(errs, "; ")
		return fmt.Errorf("stop: %s", e.lastError)
	}
	e.lastError = ""
	return nil
}

// SetTunnel brings a tunnel up or down and re-converges routing around it.
func (e *Engine) SetTunnel(ctx context.Context, name string, up bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	t, ok := e.cfg.Tunnel(name)
	if !ok {
		return fmt.Errorf("unknown tunnel %q", name)
	}

	var err error
	if up {
		err = e.vpn.Up(ctx, *t)
	} else {
		err = e.vpn.Down(ctx, *t)
	}
	if err != nil {
		e.lastError = err.Error()
		return err
	}

	// Routes that depend on this tunnel are now valid or invalid; re-converge.
	return e.applyLocked(ctx)
}

// SetRuleEnabled toggles a routing rule and applies the change immediately.
func (e *Engine) SetRuleEnabled(ctx context.Context, id string, enabled bool) error {
	return e.mutate(ctx, func() error {
		r, ok := e.cfg.Rule(id)
		if !ok {
			return fmt.Errorf("unknown rule %q", id)
		}
		r.Enabled = enabled
		return nil
	})
}

// SetRuleTarget repoints a routing rule at a different tunnel.
func (e *Engine) SetRuleTarget(ctx context.Context, id, target string) error {
	return e.mutate(ctx, func() error {
		r, ok := e.cfg.Rule(id)
		if !ok {
			return fmt.Errorf("unknown rule %q", id)
		}
		r.Target = target
		return nil
	})
}

// UpsertRule adds or replaces a routing rule.
func (e *Engine) UpsertRule(ctx context.Context, rule config.Rule) error {
	return e.mutate(ctx, func() error {
		if existing, ok := e.cfg.Rule(rule.ID); ok {
			*existing = rule
			return nil
		}
		e.cfg.Rules = append(e.cfg.Rules, rule)
		return nil
	})
}

func (e *Engine) DeleteRule(ctx context.Context, id string) error {
	return e.mutate(ctx, func() error {
		for i := range e.cfg.Rules {
			if e.cfg.Rules[i].ID == id {
				e.cfg.Rules = append(e.cfg.Rules[:i], e.cfg.Rules[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("unknown rule %q", id)
	})
}

// SetDNSRuleEnabled toggles a domain override; this reloads dnsmasq in place.
func (e *Engine) SetDNSRuleEnabled(ctx context.Context, domain string, enabled bool) error {
	return e.mutate(ctx, func() error {
		d, ok := e.cfg.DNSRule(domain)
		if !ok {
			return fmt.Errorf("unknown dns rule %q", domain)
		}
		d.Enabled = enabled
		return nil
	})
}

// UpsertDNSRule adds or replaces a domain override.
func (e *Engine) UpsertDNSRule(ctx context.Context, rule config.DNSRule) error {
	return e.mutate(ctx, func() error {
		if existing, ok := e.cfg.DNSRule(rule.Domain); ok {
			*existing = rule
			return nil
		}
		e.cfg.DNSRules = append(e.cfg.DNSRules, rule)
		return nil
	})
}

func (e *Engine) DeleteDNSRule(ctx context.Context, domain string) error {
	return e.mutate(ctx, func() error {
		for i := range e.cfg.DNSRules {
			if e.cfg.DNSRules[i].Domain == domain {
				e.cfg.DNSRules = append(e.cfg.DNSRules[:i], e.cfg.DNSRules[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("unknown dns rule %q", domain)
	})
}

// UpsertTunnel adds or replaces a tunnel definition.
func (e *Engine) UpsertTunnel(ctx context.Context, t config.Tunnel) error {
	return e.mutate(ctx, func() error {
		if existing, ok := e.cfg.Tunnel(t.Name); ok {
			// Callers that only know the profile leave TableID unset; reusing the
			// existing one keeps the tunnel's routes where the rules expect them.
			if t.TableID == 0 {
				t.TableID = existing.TableID
			}
			*existing = t
			return nil
		}
		if t.TableID == 0 {
			t.TableID = e.freeTableID()
		}
		e.cfg.Tunnels = append(e.cfg.Tunnels, t)
		return nil
	})
}

func (e *Engine) DeleteTunnel(ctx context.Context, name string) error {
	return e.mutate(ctx, func() error {
		for _, r := range e.cfg.Rules {
			if r.Target == name {
				return fmt.Errorf("rule %q still targets tunnel %q", r.ID, name)
			}
		}
		for i := range e.cfg.Tunnels {
			if e.cfg.Tunnels[i].Name == name {
				// Leave no routes behind in the table we are abandoning.
				_ = e.rt.FlushTable(ctx, e.cfg.Tunnels[i].TableID)
				e.cfg.Tunnels = append(e.cfg.Tunnels[:i], e.cfg.Tunnels[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("unknown tunnel %q", name)
	})
}

func (e *Engine) freeTableID() int {
	used := map[int]bool{}
	for _, t := range e.cfg.Tunnels {
		used[t.TableID] = true
	}
	for id := 200; id <= 252; id++ {
		if !used[id] {
			return id
		}
	}
	return 0
}

// SetFallback replaces the default upstream resolvers.
func (e *Engine) SetFallback(ctx context.Context, servers []string) error {
	return e.mutate(ctx, func() error {
		e.cfg.DNS.Fallback = servers
		return nil
	})
}

// mutate applies a config change transactionally: the edit is validated and
// persisted before any system state is touched, and rolled back if invalid.
func (e *Engine) mutate(ctx context.Context, fn func() error) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	backup := e.cfg.Clone()
	if err := fn(); err != nil {
		e.cfg = backup
		return err
	}
	if err := e.cfg.Validate(); err != nil {
		e.cfg = backup
		return err
	}
	if err := e.save(); err != nil {
		e.cfg = backup
		return fmt.Errorf("save config: %w", err)
	}
	return e.applyLocked(ctx)
}

// Reload re-reads the config file from disk, discarding nothing that was saved.
func (e *Engine) Reload(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	cfg, err := config.Load(e.cfgPath)
	if err != nil {
		return err
	}
	e.cfg = cfg
	return e.applyLocked(ctx)
}

// NMProfiles lists NetworkManager connections that could back a new tunnel.
func (e *Engine) NMProfiles(ctx context.Context) ([]vpn.NMProfile, error) {
	return e.vpn.ListNMProfiles(ctx)
}

// TunnelInterfaces lists tunnel-like devices that could back a manual tunnel,
// covering VPNs that neither NetworkManager nor wg-quick owns.
func (e *Engine) TunnelInterfaces(ctx context.Context) ([]vpn.Interface, error) {
	return e.vpn.ListTunnelInterfaces(ctx)
}

// WireGuardProfiles lists /etc/wireguard configs that could back a new tunnel.
func (e *Engine) WireGuardProfiles() []string {
	return confNames("/etc/wireguard")
}

// AmneziaProfiles lists AmneziaWG configs that could back a new tunnel.
func (e *Engine) AmneziaProfiles() []string {
	return confNames(config.AmneziaDir)
}

// confNames lists the bare profile names a wg-quick-style tool accepts.
func confNames(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, entry := range entries {
		if name, ok := strings.CutSuffix(entry.Name(), ".conf"); ok {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
