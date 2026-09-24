// Package api exposes the engine over a Unix socket.
//
// The daemon runs as root because routing and DNS changes require it. The
// socket is group-owned so the desktop GUI can drive it without prompting for
// a password on every toggle, which is what makes real-time control usable.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/maks/dual-vpn-router/internal/config"
	"github.com/maks/dual-vpn-router/internal/engine"
	"github.com/maks/dual-vpn-router/internal/vpn"
)

// DefaultSocket is where the daemon listens and the GUI connects.
const DefaultSocket = "/run/dual-vpn/dual-vpn.sock"

// DefaultGroup owns the socket; members may control the router.
const DefaultGroup = "dual-vpn"

type TunnelToggle struct {
	Name string `json:"name"`
	Up   bool   `json:"up"`
}

type RuleToggle struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
}

type RuleTarget struct {
	ID     string `json:"id"`
	Target string `json:"target"`
}

type DNSToggle struct {
	Domain  string `json:"domain"`
	Enabled bool   `json:"enabled"`
}

type NameRef struct {
	Name string `json:"name"`
}

type IDRef struct {
	ID string `json:"id"`
}

type DomainRef struct {
	Domain string `json:"domain"`
}

type Fallback struct {
	Servers []string `json:"servers"`
}

// Profiles lists what the host could plausibly be configured to use.
type Profiles struct {
	NetworkManager []vpn.NMProfile `json:"network_manager"`
	WireGuard      []string        `json:"wireguard"`
	Amnezia        []string        `json:"amnezia"`
	// Interfaces backs manual tunnels: VPNs raised by something this daemon
	// cannot drive show up only as a kernel device.
	Interfaces []vpn.Interface `json:"interfaces"`
}

type errorBody struct {
	Error string `json:"error"`
}

// Server wires the engine to an HTTP handler over a Unix socket.
type Server struct {
	eng  *engine.Engine
	ln   net.Listener
	http *http.Server
}

// NewServer binds the socket and applies ownership so the given group can use it.
func NewServer(eng *engine.Engine, socketPath, group string) (*Server, error) {
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create socket dir: %w", err)
	}
	// A stale socket from an unclean shutdown would block the bind.
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove stale socket: %w", err)
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", socketPath, err)
	}

	if err := applysocketOwnership(socketPath, group); err != nil {
		ln.Close()
		return nil, err
	}

	s := &Server{eng: eng, ln: ln}
	s.http = &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s, nil
}

// applysocketOwnership restricts the socket to root and one group. If the group
// does not exist the socket stays root-only rather than being world-writable,
// since a writable socket is root-equivalent access to routing and DNS.
func applysocketOwnership(socketPath, group string) error {
	if group == "" {
		return os.Chmod(socketPath, 0o600)
	}

	g, err := user.LookupGroup(group)
	if err != nil {
		if err := os.Chmod(socketPath, 0o600); err != nil {
			return err
		}
		return nil
	}

	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return fmt.Errorf("parse gid for group %q: %w", group, err)
	}
	if err := os.Chown(socketPath, 0, gid); err != nil {
		return fmt.Errorf("chown socket to group %q: %w", group, err)
	}
	if err := os.Chmod(socketPath, 0o660); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}
	return nil
}

// Serve runs until the context is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	errc := make(chan error, 1)
	go func() { errc <- s.http.Serve(s.ln) }()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.http.Shutdown(shutdownCtx)
	case err := <-errc:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /v1/state", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.eng.State(r.Context()))
	})

	mux.HandleFunc("GET /v1/profiles", func(w http.ResponseWriter, r *http.Request) {
		nm, err := s.eng.NMProfiles(r.Context())
		if err != nil {
			writeError(w, err)
			return
		}
		ifaces, err := s.eng.TunnelInterfaces(r.Context())
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, Profiles{
			NetworkManager: nm,
			WireGuard:      s.eng.WireGuardProfiles(),
			Amnezia:        s.eng.AmneziaProfiles(),
			Interfaces:     ifaces,
		})
	})

	s.action(mux, "POST /v1/start", func(ctx context.Context) error { return s.eng.Start(ctx) })
	s.action(mux, "POST /v1/stop", func(ctx context.Context) error { return s.eng.Stop(ctx) })
	s.action(mux, "POST /v1/apply", func(ctx context.Context) error { return s.eng.Apply(ctx) })
	s.action(mux, "POST /v1/reload", func(ctx context.Context) error { return s.eng.Reload(ctx) })

	bind(s, mux, "POST /v1/tunnel", func(ctx context.Context, b TunnelToggle) error {
		return s.eng.SetTunnel(ctx, b.Name, b.Up)
	})
	bind(s, mux, "POST /v1/tunnel/upsert", func(ctx context.Context, b config.Tunnel) error {
		return s.eng.UpsertTunnel(ctx, b)
	})
	bind(s, mux, "POST /v1/tunnel/delete", func(ctx context.Context, b NameRef) error {
		return s.eng.DeleteTunnel(ctx, b.Name)
	})

	bind(s, mux, "POST /v1/rule", func(ctx context.Context, b RuleToggle) error {
		return s.eng.SetRuleEnabled(ctx, b.ID, b.Enabled)
	})
	bind(s, mux, "POST /v1/rule/target", func(ctx context.Context, b RuleTarget) error {
		return s.eng.SetRuleTarget(ctx, b.ID, b.Target)
	})
	bind(s, mux, "POST /v1/rule/upsert", func(ctx context.Context, b config.Rule) error {
		return s.eng.UpsertRule(ctx, b)
	})
	bind(s, mux, "POST /v1/rule/delete", func(ctx context.Context, b IDRef) error {
		return s.eng.DeleteRule(ctx, b.ID)
	})

	bind(s, mux, "POST /v1/dns", func(ctx context.Context, b DNSToggle) error {
		return s.eng.SetDNSRuleEnabled(ctx, b.Domain, b.Enabled)
	})
	bind(s, mux, "POST /v1/dns/upsert", func(ctx context.Context, b config.DNSRule) error {
		return s.eng.UpsertDNSRule(ctx, b)
	})
	bind(s, mux, "POST /v1/dns/delete", func(ctx context.Context, b DomainRef) error {
		return s.eng.DeleteDNSRule(ctx, b.Domain)
	})
	bind(s, mux, "POST /v1/dns/fallback", func(ctx context.Context, b Fallback) error {
		return s.eng.SetFallback(ctx, b.Servers)
	})

	return mux
}

// action registers a handler that takes no request body and replies with state.
func (s *Server) action(mux *http.ServeMux, pattern string, fn func(context.Context) error) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if err := fn(r.Context()); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, s.eng.State(r.Context()))
	})
}

// bind registers a handler that decodes a typed body and replies with the
// resulting state, so a caller never has to make a second round trip to refresh.
func bind[T any](s *Server, mux *http.ServeMux, pattern string, fn func(context.Context, T) error) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		var body T
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "decode body: " + err.Error()})
			return
		}
		if err := fn(r.Context(), body); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, s.eng.State(r.Context()))
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusInternalServerError, errorBody{Error: err.Error()})
}

// Client talks to the daemon over the Unix socket.
type Client struct {
	http *http.Client
}

func NewClient(socketPath string) *Client {
	return &Client{
		http: &http.Client{
			Timeout: 90 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				},
			},
		},
	}
}

// the host in these URLs is ignored; the transport always dials the socket.
const socketBase = "http://dual-vpn"

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, socketBase+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("daemon unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var e errorBody
		if err := json.NewDecoder(resp.Body).Decode(&e); err == nil && e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("daemon returned %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) State(ctx context.Context) (engine.State, error) {
	var st engine.State
	err := c.do(ctx, http.MethodGet, "/v1/state", nil, &st)
	return st, err
}

func (c *Client) Profiles(ctx context.Context) (Profiles, error) {
	var p Profiles
	err := c.do(ctx, http.MethodGet, "/v1/profiles", nil, &p)
	return p, err
}

func (c *Client) Start(ctx context.Context) (engine.State, error)  { return c.post(ctx, "/v1/start", nil) }
func (c *Client) Stop(ctx context.Context) (engine.State, error)   { return c.post(ctx, "/v1/stop", nil) }
func (c *Client) Apply(ctx context.Context) (engine.State, error)  { return c.post(ctx, "/v1/apply", nil) }
func (c *Client) Reload(ctx context.Context) (engine.State, error) { return c.post(ctx, "/v1/reload", nil) }

func (c *Client) SetTunnel(ctx context.Context, name string, up bool) (engine.State, error) {
	return c.post(ctx, "/v1/tunnel", TunnelToggle{Name: name, Up: up})
}

func (c *Client) UpsertTunnel(ctx context.Context, t config.Tunnel) (engine.State, error) {
	return c.post(ctx, "/v1/tunnel/upsert", t)
}

func (c *Client) DeleteTunnel(ctx context.Context, name string) (engine.State, error) {
	return c.post(ctx, "/v1/tunnel/delete", NameRef{Name: name})
}

func (c *Client) SetRule(ctx context.Context, id string, enabled bool) (engine.State, error) {
	return c.post(ctx, "/v1/rule", RuleToggle{ID: id, Enabled: enabled})
}

func (c *Client) SetRuleTarget(ctx context.Context, id, target string) (engine.State, error) {
	return c.post(ctx, "/v1/rule/target", RuleTarget{ID: id, Target: target})
}

func (c *Client) UpsertRule(ctx context.Context, r config.Rule) (engine.State, error) {
	return c.post(ctx, "/v1/rule/upsert", r)
}

func (c *Client) DeleteRule(ctx context.Context, id string) (engine.State, error) {
	return c.post(ctx, "/v1/rule/delete", IDRef{ID: id})
}

func (c *Client) SetDNSRule(ctx context.Context, domain string, enabled bool) (engine.State, error) {
	return c.post(ctx, "/v1/dns", DNSToggle{Domain: domain, Enabled: enabled})
}

func (c *Client) UpsertDNSRule(ctx context.Context, d config.DNSRule) (engine.State, error) {
	return c.post(ctx, "/v1/dns/upsert", d)
}

func (c *Client) DeleteDNSRule(ctx context.Context, domain string) (engine.State, error) {
	return c.post(ctx, "/v1/dns/delete", DomainRef{Domain: domain})
}

func (c *Client) SetFallback(ctx context.Context, servers []string) (engine.State, error) {
	return c.post(ctx, "/v1/dns/fallback", Fallback{Servers: servers})
}

func (c *Client) post(ctx context.Context, path string, body any) (engine.State, error) {
	var st engine.State
	err := c.do(ctx, http.MethodPost, path, body, &st)
	return st, err
}
