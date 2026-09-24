// Package dns drives a dnsmasq instance that answers split-horizon queries.
//
// The split lives entirely inside dnsmasq: systemd-resolved is pointed at
// dnsmasq for every domain, and dnsmasq decides per-domain which upstream to
// use. Toggling one domain therefore rewrites a single file and sends SIGHUP,
// with no resolver restart and no edits to /etc/resolv.conf.
package dns

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	baseConfigPath   = "/etc/dnsmasq.d/dual-vpn.conf"
	serversFilePath  = "/var/lib/dual-vpn/servers.conf"
	resolvedDropPath = "/etc/systemd/resolved.conf.d/dual-vpn.conf"
)

// Entry maps a domain onto the upstream resolvers that are authoritative for it.
type Entry struct {
	Domain  string
	Servers []string
}

type Manager struct {
	BaseConfig   string
	ServersFile  string
	ResolvedDrop string
}

func New() *Manager {
	return &Manager{
		BaseConfig:   baseConfigPath,
		ServersFile:  serversFilePath,
		ResolvedDrop: resolvedDropPath,
	}
}

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

// renderBase builds the static dnsmasq config. It changes only when the listen
// address changes, which is what lets the common case avoid a restart.
func renderBase(listenAddr, serversFile string) []byte {
	var b strings.Builder
	b.WriteString("# Managed by dual-vpn. Do not edit.\n")
	b.WriteString("listen-address=" + listenAddr + "\n")
	// Without bind-interfaces dnsmasq binds the wildcard address and collides
	// with systemd-resolved on 127.0.0.53:53.
	b.WriteString("bind-interfaces\n")
	// Never read /etc/resolv.conf: it points back at systemd-resolved, which
	// forwards here, which would be a resolution loop.
	b.WriteString("no-resolv\n")
	b.WriteString("cache-size=1000\n")
	b.WriteString("servers-file=" + serversFile + "\n")
	return []byte(b.String())
}

// renderServers builds the hot-reloadable upstream list.
func renderServers(entries []Entry, fallback []string) []byte {
	var b strings.Builder
	b.WriteString("# Managed by dual-vpn. Reloaded on SIGHUP.\n")
	for _, e := range entries {
		for _, s := range e.Servers {
			fmt.Fprintf(&b, "server=/%s/%s\n", e.Domain, s)
		}
	}
	// Bare server= lines catch everything not matched by a domain above.
	for _, s := range fallback {
		fmt.Fprintf(&b, "server=%s\n", s)
	}
	return []byte(b.String())
}

// renderResolved points systemd-resolved at dnsmasq for all names. Routing the
// whole namespace here keeps per-domain changes inside dnsmasq, so resolved
// never needs restarting when a domain is toggled.
func renderResolved(listenAddr string) []byte {
	var b strings.Builder
	b.WriteString("# Managed by dual-vpn. Do not edit.\n")
	b.WriteString("[Resolve]\n")
	b.WriteString("DNS=" + listenAddr + "\n")
	b.WriteString("Domains=~.\n")
	return []byte(b.String())
}

// writeIfChanged writes atomically and reports whether the content differed.
func writeIfChanged(path string, data []byte, perm os.FileMode) (bool, error) {
	if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, data) {
		return false, nil
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(dir, ".dual-vpn-*")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return false, err
	}
	return true, nil
}

// Apply converges DNS on the given entries, reloading rather than restarting
// whenever only the upstream list changed.
func (m *Manager) Apply(ctx context.Context, listenAddr string, entries []Entry, fallback []string) error {
	baseChanged, err := writeIfChanged(m.BaseConfig, renderBase(listenAddr, m.ServersFile), 0o644)
	if err != nil {
		return fmt.Errorf("write dnsmasq config: %w", err)
	}
	if _, err := writeIfChanged(m.ServersFile, renderServers(entries, fallback), 0o644); err != nil {
		return fmt.Errorf("write servers file: %w", err)
	}

	resolvedChanged, err := writeIfChanged(m.ResolvedDrop, renderResolved(listenAddr), 0o644)
	if err != nil {
		return fmt.Errorf("write resolved drop-in: %w", err)
	}

	switch {
	case baseChanged || !m.Running(ctx):
		if _, err := run(ctx, "systemctl", "restart", "dnsmasq"); err != nil {
			return fmt.Errorf("restart dnsmasq: %w", err)
		}
	default:
		if err := m.Reload(ctx); err != nil {
			return err
		}
	}

	if resolvedChanged {
		if _, err := run(ctx, "systemctl", "restart", "systemd-resolved"); err != nil {
			return fmt.Errorf("restart systemd-resolved: %w", err)
		}
	}
	return nil
}

// Reload makes dnsmasq re-read the servers file without dropping its cache
// or its listening socket.
func (m *Manager) Reload(ctx context.Context) error {
	if _, err := run(ctx, "systemctl", "reload", "dnsmasq"); err != nil {
		return fmt.Errorf("reload dnsmasq: %w", err)
	}
	return nil
}

func (m *Manager) Running(ctx context.Context) bool {
	out, err := exec.CommandContext(ctx, "systemctl", "is-active", "dnsmasq").CombinedOutput()
	// is-active exits non-zero for inactive, so trust the payload rather than err.
	_ = err
	return strings.TrimSpace(string(out)) == "active"
}

// Cleanup removes our configuration and hands DNS back to systemd-resolved.
func (m *Manager) Cleanup(ctx context.Context) error {
	var errs []string

	for _, p := range []string{m.BaseConfig, m.ServersFile, m.ResolvedDrop} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Sprintf("remove %s: %s", p, err))
		}
	}
	if _, err := run(ctx, "systemctl", "stop", "dnsmasq"); err != nil {
		errs = append(errs, fmt.Sprintf("stop dnsmasq: %s", err))
	}
	// Restoring resolved's own configuration is what puts DNS back; we never
	// touched /etc/resolv.conf, so there is nothing else to undo.
	if _, err := run(ctx, "systemctl", "restart", "systemd-resolved"); err != nil {
		errs = append(errs, fmt.Sprintf("restart systemd-resolved: %s", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("dns cleanup: %s", strings.Join(errs, "; "))
	}
	return nil
}
