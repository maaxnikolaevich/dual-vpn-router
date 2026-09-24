package routing

import (
	"sort"
	"testing"
)

func TestParseManagedRulesIgnoresSystemRules(t *testing.T) {
	// Real `ip -j rule show` output from a host that already runs WireGuard,
	// with two of our rules mixed in.
	data := []byte(`[
	 {"priority":0,"src":"all","table":"local"},
	 {"priority":9000,"not":null,"src":"all","fwmark":"0xc8","table":"200"},
	 {"priority":10024,"src":"all","dst":"10.0.0.0","dstlen":8,"table":"200"},
	 {"priority":32762,"not":null,"src":"all","fwmark":"0xca6c","table":"51820"},
	 {"priority":32766,"src":"all","table":"main"},
	 {"priority":32767,"src":"all","table":"default"}
	]`)

	got, err := parseManagedRules(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d managed rules, want 2: %+v", len(got), got)
	}

	keys := []string{got[0].key(), got[1].key()}
	sort.Strings(keys)
	want := []string{"mark:200:200", "to:10.0.0.0/8:200"}
	for i := range want {
		if keys[i] != want[i] {
			t.Errorf("key %d = %q, want %q", i, keys[i], want[i])
		}
	}
}

func TestParseManagedRulesSkipsWireGuardBand(t *testing.T) {
	// The pre-existing WireGuard rule at 32762 must never be adopted, otherwise
	// cleanup would tear down someone else's tunnel.
	data := []byte(`[{"priority":32762,"src":"all","fwmark":"0xca6c","table":"51820"}]`)
	got, err := parseManagedRules(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("adopted a rule outside our band: %+v", got)
	}
}

func TestParseManagedRulesSkipsNamedTables(t *testing.T) {
	// A rule in our band pointing at a named table was not created by us.
	data := []byte(`[{"priority":10000,"src":"all","dst":"10.0.0.0","dstlen":8,"table":"main"}]`)
	got, err := parseManagedRules(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("adopted a named-table rule: %+v", got)
	}
}

func TestPriorityOrdersSpecificFirst(t *testing.T) {
	host := RuleSpec{To: "10.0.16.1/32", TableID: 200}
	wide := RuleSpec{To: "10.0.0.0/8", TableID: 200}
	mark := RuleSpec{Fwmark: 200, TableID: 200}

	if host.priority() >= wide.priority() {
		t.Errorf("/32 priority %d should be lower (matched earlier) than /8 priority %d",
			host.priority(), wide.priority())
	}
	if mark.priority() >= host.priority() {
		t.Errorf("fwmark priority %d should precede cidr priority %d",
			mark.priority(), host.priority())
	}
	for _, r := range []RuleSpec{host, wide, mark} {
		if r.priority() < PrioMin || r.priority() > PrioMax {
			t.Errorf("priority %d escapes the managed band %d-%d", r.priority(), PrioMin, PrioMax)
		}
	}
}

func TestNormalizeCIDRMakesDiffsStable(t *testing.T) {
	tests := []struct{ in, want string }{
		// The kernel reports host routes bare; config writes them with /32.
		{"10.0.16.1", "10.0.16.1/32"},
		{"10.0.16.1/32", "10.0.16.1/32"},
		// Non-canonical input must land on the same string as canonical input.
		{"10.1.2.3/8", "10.0.0.0/8"},
		{"10.0.0.0/8", "10.0.0.0/8"},
	}
	for _, tc := range tests {
		if got := normalizeCIDR(tc.in); got != tc.want {
			t.Errorf("normalizeCIDR(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestKeyMatchesAcrossRepresentations(t *testing.T) {
	// A rule read back from the kernel must diff equal to the configured one,
	// otherwise reconcile would delete and re-add it on every pass.
	fromConfig := RuleSpec{To: "10.0.16.1/32", TableID: 200}
	fromKernel := RuleSpec{To: "10.0.16.1", TableID: 200}
	if fromConfig.key() != fromKernel.key() {
		t.Errorf("keys differ: %q vs %q", fromConfig.key(), fromKernel.key())
	}
}
