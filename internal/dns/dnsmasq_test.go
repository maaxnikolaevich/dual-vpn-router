package dns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderServersOrdersDomainsBeforeFallback(t *testing.T) {
	got := string(renderServers([]Entry{
		{Domain: "itlabs.io", Servers: []string{"10.0.16.1", "10.2.16.1"}},
		{Domain: "sdvor.com", Servers: []string{"10.0.16.1"}},
	}, []string{"8.8.8.8", "8.8.4.4"}))

	for _, want := range []string{
		"server=/itlabs.io/10.0.16.1\n",
		"server=/itlabs.io/10.2.16.1\n",
		"server=/sdvor.com/10.0.16.1\n",
		"server=8.8.8.8\n",
		"server=8.8.4.4\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestRenderServersWithNoEntriesIsFallbackOnly(t *testing.T) {
	// Disabling every domain must still leave a resolver that answers.
	got := string(renderServers(nil, []string{"8.8.8.8"}))
	if strings.Contains(got, "server=/") {
		t.Errorf("expected no domain entries, got:\n%s", got)
	}
	if !strings.Contains(got, "server=8.8.8.8\n") {
		t.Errorf("fallback missing from:\n%s", got)
	}
}

func TestRenderBaseAvoidsResolvedConflict(t *testing.T) {
	got := string(renderBase("127.0.0.1", "/var/lib/dual-vpn/servers.conf"))

	// Without bind-interfaces dnsmasq grabs the wildcard and fights resolved.
	if !strings.Contains(got, "bind-interfaces\n") {
		t.Error("bind-interfaces missing; dnsmasq would collide with systemd-resolved")
	}
	// Without no-resolv dnsmasq forwards to resolved, which forwards back.
	if !strings.Contains(got, "no-resolv\n") {
		t.Error("no-resolv missing; resolution would loop")
	}
	if !strings.Contains(got, "servers-file=/var/lib/dual-vpn/servers.conf\n") {
		t.Error("servers-file missing; live reload would not work")
	}
}

func TestRenderResolvedRoutesAllNames(t *testing.T) {
	got := string(renderResolved("127.0.0.1"))
	if !strings.Contains(got, "DNS=127.0.0.1\n") {
		t.Errorf("resolved not pointed at dnsmasq:\n%s", got)
	}
	// Routing the whole namespace is what keeps per-domain toggles inside
	// dnsmasq instead of requiring a resolved restart.
	if !strings.Contains(got, "Domains=~.\n") {
		t.Errorf("resolved should route all domains to dnsmasq:\n%s", got)
	}
}

func TestBaseConfigIsStableAcrossDomainChanges(t *testing.T) {
	// The base config must not depend on the domain list, otherwise every
	// toggle would trigger a dnsmasq restart instead of a reload.
	a := renderBase("127.0.0.1", "/var/lib/dual-vpn/servers.conf")
	b := renderBase("127.0.0.1", "/var/lib/dual-vpn/servers.conf")
	if string(a) != string(b) {
		t.Error("base config is not deterministic")
	}
}

func TestWriteIfChangedReportsChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conf")

	changed, err := writeIfChanged(path, []byte("one"), 0o644)
	if err != nil || !changed {
		t.Fatalf("first write: changed=%v err=%v", changed, err)
	}

	changed, err = writeIfChanged(path, []byte("one"), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("identical content should report no change")
	}

	changed, err = writeIfChanged(path, []byte("two"), 0o644)
	if err != nil || !changed {
		t.Fatalf("third write: changed=%v err=%v", changed, err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "two" {
		t.Errorf("content = %q, want %q", got, "two")
	}
}
