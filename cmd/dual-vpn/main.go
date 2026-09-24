// Command dual-vpn manages policy-based routing and split DNS across multiple
// VPN tunnels. It runs either as a root daemon that the GUI drives over a Unix
// socket, or as a one-shot CLI.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/maks/dual-vpn-router/internal/api"
	"github.com/maks/dual-vpn-router/internal/config"
	"github.com/maks/dual-vpn-router/internal/engine"
	"github.com/spf13/cobra"
)

const defaultConfigPath = "/etc/dual-vpn/config.yaml"

// reconcileInterval re-converges routing so a tunnel that reconnects with a new
// interface or gateway is picked up without user action.
const reconcileInterval = 15 * time.Second

var (
	configPath string
	socketPath string
	socketGrp  string
)

func main() {
	root := &cobra.Command{
		Use:          "dual-vpn",
		Short:        "Route selected destinations and domains through chosen VPN tunnels",
		SilenceUsage: true,
		// main already prints the error; cobra printing it too would duplicate it.
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVarP(&configPath, "config", "c", defaultConfigPath, "Configuration file")
	root.PersistentFlags().StringVar(&socketPath, "socket", api.DefaultSocket, "Daemon control socket")

	daemonCmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run the control daemon (requires root)",
		RunE:  runDaemon,
	}
	daemonCmd.Flags().StringVar(&socketGrp, "socket-group", api.DefaultGroup,
		"Unix group allowed to control the daemon")

	root.AddCommand(
		daemonCmd,
		&cobra.Command{
			Use:   "init",
			Short: "Write a default configuration file",
			RunE:  runInit,
		},
		&cobra.Command{
			Use:   "status",
			Short: "Show tunnels, routing rules and DNS overrides",
			RunE:  runStatus,
		},
		simpleCmd("start", "Apply routing and DNS", func(ctx context.Context, c controller) error {
			return c.start(ctx)
		}),
		simpleCmd("stop", "Remove everything this tool installed", func(ctx context.Context, c controller) error {
			return c.stop(ctx)
		}),
		simpleCmd("apply", "Re-converge the system on the configuration", func(ctx context.Context, c controller) error {
			return c.apply(ctx)
		}),
		// Retained so existing muscle memory and docs keep working.
		hiddenAlias("setup", "start"),
		hiddenAlias("cleanup", "stop"),
		tunnelCmd(),
		ruleCmd(),
		dnsCmd(),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runInit(cmd *cobra.Command, _ []string) error {
	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("%s already exists; edit it or delete it first", configPath)
	}
	if err := config.Save(config.DefaultConfig(), configPath); err != nil {
		return err
	}
	fmt.Printf("Wrote %s. Edit it, then run: sudo dual-vpn start\n", configPath)
	return nil
}

func runDaemon(cmd *cobra.Command, _ []string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("the daemon must run as root")
	}

	eng, err := engine.New(configPath)
	if err != nil {
		return err
	}

	srv, err := api.NewServer(eng, socketPath, socketGrp)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Converge once at startup so a reboot restores the previous state.
	if err := eng.Apply(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "warning:", err)
	}

	go func() {
		ticker := time.NewTicker(reconcileInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := eng.Apply(ctx); err != nil {
					fmt.Fprintln(os.Stderr, "reconcile:", err)
				}
			}
		}
	}()

	fmt.Printf("dual-vpn daemon listening on %s\n", socketPath)
	// Routing is intentionally left in place on exit so a daemon restart or
	// crash cannot silently drop traffic out of its tunnel.
	return srv.Serve(ctx)
}

// controller abstracts over driving the daemon versus acting directly, so the
// CLI works whether or not the daemon is running.
type controller interface {
	state(ctx context.Context) (engine.State, error)
	start(ctx context.Context) error
	stop(ctx context.Context) error
	apply(ctx context.Context) error
	setTunnel(ctx context.Context, name string, up bool) error
	setRule(ctx context.Context, id string, enabled bool) error
	setRuleTarget(ctx context.Context, id, target string) error
	setDNS(ctx context.Context, domain string, enabled bool) error
}

type clientController struct{ c *api.Client }

func (t clientController) state(ctx context.Context) (engine.State, error) { return t.c.State(ctx) }
func (t clientController) start(ctx context.Context) error {
	_, err := t.c.Start(ctx)
	return err
}
func (t clientController) stop(ctx context.Context) error {
	_, err := t.c.Stop(ctx)
	return err
}
func (t clientController) apply(ctx context.Context) error {
	_, err := t.c.Apply(ctx)
	return err
}
func (t clientController) setTunnel(ctx context.Context, name string, up bool) error {
	_, err := t.c.SetTunnel(ctx, name, up)
	return err
}
func (t clientController) setRule(ctx context.Context, id string, enabled bool) error {
	_, err := t.c.SetRule(ctx, id, enabled)
	return err
}
func (t clientController) setRuleTarget(ctx context.Context, id, target string) error {
	_, err := t.c.SetRuleTarget(ctx, id, target)
	return err
}
func (t clientController) setDNS(ctx context.Context, domain string, enabled bool) error {
	_, err := t.c.SetDNSRule(ctx, domain, enabled)
	return err
}

type engineController struct{ e *engine.Engine }

func (t engineController) state(ctx context.Context) (engine.State, error) {
	return t.e.State(ctx), nil
}
func (t engineController) start(ctx context.Context) error { return t.e.Start(ctx) }
func (t engineController) stop(ctx context.Context) error  { return t.e.Stop(ctx) }
func (t engineController) apply(ctx context.Context) error { return t.e.Apply(ctx) }
func (t engineController) setTunnel(ctx context.Context, name string, up bool) error {
	return t.e.SetTunnel(ctx, name, up)
}
func (t engineController) setRule(ctx context.Context, id string, enabled bool) error {
	return t.e.SetRuleEnabled(ctx, id, enabled)
}
func (t engineController) setRuleTarget(ctx context.Context, id, target string) error {
	return t.e.SetRuleTarget(ctx, id, target)
}
func (t engineController) setDNS(ctx context.Context, domain string, enabled bool) error {
	return t.e.SetDNSRuleEnabled(ctx, domain, enabled)
}

// connect prefers the running daemon; without it the command acts directly,
// which needs root because it touches routing and DNS itself.
func connect() (controller, error) {
	if _, err := os.Stat(socketPath); err == nil {
		return clientController{c: api.NewClient(socketPath)}, nil
	}
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("daemon is not running at %s; either start it or re-run with sudo", socketPath)
	}
	eng, err := engine.New(configPath)
	if err != nil {
		return nil, err
	}
	return engineController{e: eng}, nil
}

func simpleCmd(use, short string, fn func(context.Context, controller) error) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := connect()
			if err != nil {
				return err
			}
			if err := fn(cmd.Context(), c); err != nil {
				return err
			}
			return printState(cmd.Context(), c)
		},
	}
}

func hiddenAlias(use, target string) *cobra.Command {
	return &cobra.Command{
		Use:    use,
		Short:  fmt.Sprintf("Deprecated alias for %q", target),
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(os.Stderr, "note: %q is now %q\n", use, target)
			c, err := connect()
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			if target == "start" {
				err = c.start(ctx)
			} else {
				err = c.stop(ctx)
			}
			if err != nil {
				return err
			}
			return printState(ctx, c)
		},
	}
}

func tunnelCmd() *cobra.Command {
	c := &cobra.Command{Use: "tunnel", Short: "Control VPN tunnels"}
	c.AddCommand(
		toggleCmd("up", "Bring a tunnel up", func(ctx context.Context, ct controller, name string) error {
			return ct.setTunnel(ctx, name, true)
		}),
		toggleCmd("down", "Take a tunnel down", func(ctx context.Context, ct controller, name string) error {
			return ct.setTunnel(ctx, name, false)
		}),
	)
	return c
}

func ruleCmd() *cobra.Command {
	c := &cobra.Command{Use: "rule", Short: "Control routing rules"}
	c.AddCommand(
		toggleCmd("enable", "Enable a routing rule", func(ctx context.Context, ct controller, id string) error {
			return ct.setRule(ctx, id, true)
		}),
		toggleCmd("disable", "Disable a routing rule", func(ctx context.Context, ct controller, id string) error {
			return ct.setRule(ctx, id, false)
		}),
		&cobra.Command{
			Use:   "target <rule-id> <tunnel|direct>",
			Short: "Route a rule through a different tunnel",
			Args:  cobra.ExactArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				ct, err := connect()
				if err != nil {
					return err
				}
				if err := ct.setRuleTarget(cmd.Context(), args[0], args[1]); err != nil {
					return err
				}
				return printState(cmd.Context(), ct)
			},
		},
	)
	return c
}

func dnsCmd() *cobra.Command {
	c := &cobra.Command{Use: "dns", Short: "Control per-domain DNS overrides"}
	c.AddCommand(
		toggleCmd("enable", "Enable a domain override", func(ctx context.Context, ct controller, d string) error {
			return ct.setDNS(ctx, d, true)
		}),
		toggleCmd("disable", "Disable a domain override", func(ctx context.Context, ct controller, d string) error {
			return ct.setDNS(ctx, d, false)
		}),
	)
	return c
}

func toggleCmd(use, short string, fn func(context.Context, controller, string) error) *cobra.Command {
	return &cobra.Command{
		Use:   use + " <name>",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := connect()
			if err != nil {
				return err
			}
			if err := fn(cmd.Context(), c, args[0]); err != nil {
				return err
			}
			return printState(cmd.Context(), c)
		},
	}
}

func runStatus(cmd *cobra.Command, _ []string) error {
	c, err := connect()
	if err != nil {
		return err
	}
	return printState(cmd.Context(), c)
}

func printState(ctx context.Context, c controller) error {
	st, err := c.state(ctx)
	if err != nil {
		return err
	}

	status := "stopped"
	if st.Active {
		status = "active"
	}
	fmt.Printf("Router: %s\n", status)
	if st.LastError != "" {
		fmt.Printf("Last error: %s\n", st.LastError)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)

	fmt.Fprintln(w, "\nTUNNEL\tKIND\tINTERFACE\tTABLE\tSTATE\tGATEWAY")
	for _, t := range st.Tunnels {
		state := "down"
		if t.Up {
			state = "up"
		} else if t.Present {
			state = "present"
		}
		if t.Detail != "" {
			state += " (" + t.Detail + ")"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\n",
			t.Name, t.Kind, dash(t.Interface), t.TableID, state, dash(t.Gateway))
	}

	fmt.Fprintln(w, "\nRULE\tTARGET\tENABLED\tIN FORCE\tDESTINATIONS")
	for _, r := range st.Rules {
		inForce := "no"
		if r.Applied {
			inForce = "yes"
		}
		if r.Reason != "" {
			inForce += " (" + r.Reason + ")"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			r.ID, r.Target, yesNo(r.Enabled), inForce, strings.Join(r.CIDRs, ", "))
	}

	fmt.Fprintln(w, "\nDOMAIN\tVIA\tENABLED\tIN FORCE\tSERVERS")
	for _, d := range st.DNSRules {
		inForce := "no"
		if d.Applied {
			inForce = "yes"
		}
		if d.Reason != "" {
			inForce += " (" + d.Reason + ")"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			d.Domain, dash(d.Via), yesNo(d.Enabled), inForce, strings.Join(d.Servers, ", "))
	}

	fmt.Fprintf(w, "\nFallback DNS\t%s\n", strings.Join(st.Fallback, ", "))
	return w.Flush()
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
