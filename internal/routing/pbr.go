// Package routing installs policy-based routing so individual destinations can
// be steered into per-tunnel routing tables.
//
// Two deliberate safety properties:
//
//   - Tables are addressed by numeric id only. Nothing is ever written to
//     /etc/iproute2/rt_tables, so a crash can never corrupt a system file.
//   - Every ip rule this package creates lives in a reserved priority band, and
//     every iptables rule lives in a dedicated chain. Cleanup therefore never
//     has to guess which rules belong to the system.
package routing

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

const (
	// FwmarkPrio sits above the CIDR band so marked DNS traffic is matched first.
	FwmarkPrio = 9000
	// CIDRPrioBase is offset by prefix length so specific routes beat general ones.
	CIDRPrioBase = 10000

	// PrioMin and PrioMax bound the band this package owns exclusively.
	PrioMin = 9000
	PrioMax = 10999

	// MangleChain isolates our iptables rules from everything else on the host.
	MangleChain = "DUALVPN"
)

type Manager struct{}

func New() *Manager { return &Manager{} }

func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return out, err
		}
		return out, fmt.Errorf("%s %s: %s: %s", name, strings.Join(args, " "), err, msg)
	}
	return out, nil
}

// RuleSpec is one `ip rule` entry. Exactly one of To or Fwmark is set.
type RuleSpec struct {
	To      string
	Fwmark  int
	TableID int
}

func (r RuleSpec) priority() int {
	if r.Fwmark != 0 {
		return FwmarkPrio
	}
	// Longer prefixes get a numerically lower priority, so /32 is consulted
	// before /8 regardless of the order rules were added.
	ones := 0
	if _, n, err := net.ParseCIDR(r.To); err == nil {
		ones, _ = n.Mask.Size()
	}
	return CIDRPrioBase + (32 - ones)
}

func (r RuleSpec) key() string {
	if r.Fwmark != 0 {
		return fmt.Sprintf("mark:%d:%d", r.Fwmark, r.TableID)
	}
	return fmt.Sprintf("to:%s:%d", normalizeCIDR(r.To), r.TableID)
}

// normalizeCIDR renders an address in the same form on both sides of a diff.
// The kernel reports a host route as a bare address, config supplies /32.
func normalizeCIDR(s string) string {
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "/") {
		if ip := net.ParseIP(s); ip != nil {
			if ip.To4() != nil {
				return s + "/32"
			}
			return s + "/128"
		}
		return s
	}
	if _, n, err := net.ParseCIDR(s); err == nil {
		return n.String()
	}
	return s
}

type ipRule struct {
	Priority int    `json:"priority"`
	Dst      string `json:"dst"`
	DstLen   *int   `json:"dstlen"`
	Fwmark   string `json:"fwmark"`
	Table    string `json:"table"`
}

func parseManagedRules(data []byte) ([]RuleSpec, error) {
	var raw []ipRule
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	var out []RuleSpec
	for _, r := range raw {
		if r.Priority < PrioMin || r.Priority > PrioMax {
			continue
		}
		// Our tables are always numeric; a named table is not ours.
		table, err := strconv.Atoi(r.Table)
		if err != nil {
			continue
		}

		spec := RuleSpec{TableID: table}
		switch {
		case r.Fwmark != "":
			mark, err := strconv.ParseInt(strings.TrimPrefix(r.Fwmark, "0x"), 16, 64)
			if err != nil {
				continue
			}
			spec.Fwmark = int(mark)
		case r.Dst != "" && r.Dst != "all":
			dst := r.Dst
			if r.DstLen != nil && !strings.Contains(dst, "/") {
				dst = fmt.Sprintf("%s/%d", dst, *r.DstLen)
			}
			spec.To = normalizeCIDR(dst)
		default:
			continue
		}
		out = append(out, spec)
	}
	return out, nil
}

// ListManagedRules returns only the ip rules owned by this package.
func (m *Manager) ListManagedRules(ctx context.Context) ([]RuleSpec, error) {
	out, err := run(ctx, "ip", "-j", "rule", "show")
	if err != nil {
		return nil, fmt.Errorf("list ip rules: %w", err)
	}
	return parseManagedRules(out)
}

func (m *Manager) addRule(ctx context.Context, r RuleSpec) error {
	args := []string{"rule", "add"}
	if r.Fwmark != 0 {
		args = append(args, "fwmark", strconv.Itoa(r.Fwmark))
	} else {
		args = append(args, "to", r.To)
	}
	args = append(args,
		"lookup", strconv.Itoa(r.TableID),
		"pref", strconv.Itoa(r.priority()),
	)
	_, err := run(ctx, "ip", args...)
	return err
}

func (m *Manager) delRule(ctx context.Context, r RuleSpec) error {
	args := []string{"rule", "del"}
	if r.Fwmark != 0 {
		args = append(args, "fwmark", strconv.Itoa(r.Fwmark))
	} else {
		args = append(args, "to", r.To)
	}
	args = append(args,
		"lookup", strconv.Itoa(r.TableID),
		"pref", strconv.Itoa(r.priority()),
	)
	_, err := run(ctx, "ip", args...)
	return err
}

// ReconcileRules converges the managed priority band on the desired rule set,
// touching only the entries that actually differ so live traffic is not dropped.
func (m *Manager) ReconcileRules(ctx context.Context, desired []RuleSpec) error {
	current, err := m.ListManagedRules(ctx)
	if err != nil {
		return err
	}

	want := make(map[string]RuleSpec, len(desired))
	for _, r := range desired {
		want[r.key()] = r
	}
	have := make(map[string]RuleSpec, len(current))
	for _, r := range current {
		have[r.key()] = r
	}

	// Add before delete: a destination stays reachable through the old rule
	// until its replacement is in place.
	var keys []string
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var errs []string
	for _, k := range keys {
		if _, ok := have[k]; !ok {
			if err := m.addRule(ctx, want[k]); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}

	keys = keys[:0]
	for k := range have {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		if _, ok := want[k]; !ok {
			if err := m.delRule(ctx, have[k]); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("reconcile ip rules: %s", strings.Join(errs, "; "))
	}
	return nil
}

// SetTableDefault points a table's default route at a tunnel. A gateway-less
// tunnel (WireGuard and friends) is routed by device instead.
func (m *Manager) SetTableDefault(ctx context.Context, tableID int, iface, gateway string) error {
	if iface == "" {
		return fmt.Errorf("table %d: no interface to route through", tableID)
	}

	args := []string{"route", "replace", "default"}
	if gateway != "" {
		args = append(args, "via", gateway)
	}
	args = append(args, "dev", iface, "table", strconv.Itoa(tableID))

	if _, err := run(ctx, "ip", args...); err != nil {
		return fmt.Errorf("set default route for table %d: %w", tableID, err)
	}
	return nil
}

// SetTableBlackhole makes a table drop everything it is asked to route. This
// backs fail-closed rules: while the tunnel is down, matching traffic is
// discarded rather than escaping through the default route.
func (m *Manager) SetTableBlackhole(ctx context.Context, tableID int) error {
	if _, err := run(ctx, "ip", "route", "replace", "blackhole", "default",
		"table", strconv.Itoa(tableID)); err != nil {
		return fmt.Errorf("blackhole table %d: %w", tableID, err)
	}
	return nil
}

// FlushTable empties one of our routing tables.
func (m *Manager) FlushTable(ctx context.Context, tableID int) error {
	// Flushing an already-empty table is not an error worth surfacing.
	_, err := run(ctx, "ip", "route", "flush", "table", strconv.Itoa(tableID))
	if err != nil && strings.Contains(err.Error(), "No such process") {
		return nil
	}
	return err
}

// MarkSpec steers DNS queries for one server into a tunnel's table.
type MarkSpec struct {
	Server string
	Mark   int
}

// EnsureChain creates the dedicated mangle chain and hooks it into OUTPUT once.
func (m *Manager) EnsureChain(ctx context.Context) error {
	if _, err := run(ctx, "iptables", "-t", "mangle", "-N", MangleChain); err != nil {
		// The chain already existing is the expected steady state.
		if !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("create mangle chain: %w", err)
		}
	}
	// -C tests for the jump so repeated calls cannot stack duplicates.
	if _, err := run(ctx, "iptables", "-t", "mangle", "-C", "OUTPUT", "-j", MangleChain); err != nil {
		if _, err := run(ctx, "iptables", "-t", "mangle", "-A", "OUTPUT", "-j", MangleChain); err != nil {
			return fmt.Errorf("hook mangle chain into OUTPUT: %w", err)
		}
	}
	return nil
}

// SyncDNSMarks rewrites the mark rules. Flushing is safe because the chain
// contains nothing but rules this package created.
func (m *Manager) SyncDNSMarks(ctx context.Context, specs []MarkSpec) error {
	if err := m.EnsureChain(ctx); err != nil {
		return err
	}
	if _, err := run(ctx, "iptables", "-t", "mangle", "-F", MangleChain); err != nil {
		return fmt.Errorf("flush mangle chain: %w", err)
	}

	for _, s := range specs {
		for _, proto := range []string{"udp", "tcp"} {
			_, err := run(ctx, "iptables", "-t", "mangle", "-A", MangleChain,
				"-p", proto, "--dport", "53", "-d", s.Server,
				"-j", "MARK", "--set-mark", strconv.Itoa(s.Mark))
			if err != nil {
				return fmt.Errorf("mark %s dns %s: %w", proto, s.Server, err)
			}
		}
	}
	return nil
}

// RemoveChain unhooks and deletes the mangle chain.
func (m *Manager) RemoveChain(ctx context.Context) error {
	var errs []string
	// Unhook first so no packet can traverse a chain that is being deleted.
	if _, err := run(ctx, "iptables", "-t", "mangle", "-C", "OUTPUT", "-j", MangleChain); err == nil {
		if _, err := run(ctx, "iptables", "-t", "mangle", "-D", "OUTPUT", "-j", MangleChain); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if _, err := run(ctx, "iptables", "-t", "mangle", "-F", MangleChain); err != nil {
		if !strings.Contains(err.Error(), "No chain") {
			errs = append(errs, err.Error())
		}
	}
	if _, err := run(ctx, "iptables", "-t", "mangle", "-X", MangleChain); err != nil {
		if !strings.Contains(err.Error(), "No chain") {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("remove mangle chain: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Cleanup removes every trace of this package: managed rules, our tables, and
// the mangle chain. It continues past individual failures so one wedged step
// cannot strand the host in a half-configured state.
func (m *Manager) Cleanup(ctx context.Context, tableIDs []int) error {
	var errs []string

	if err := m.ReconcileRules(ctx, nil); err != nil {
		errs = append(errs, err.Error())
	}
	for _, id := range tableIDs {
		if err := m.FlushTable(ctx, id); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if err := m.RemoveChain(ctx); err != nil {
		errs = append(errs, err.Error())
	}

	if len(errs) > 0 {
		return fmt.Errorf("routing cleanup: %s", strings.Join(errs, "; "))
	}
	return nil
}
