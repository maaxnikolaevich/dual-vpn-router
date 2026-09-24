// Command dual-vpn-gui is a GTK4/libadwaita front end for the dual-vpn daemon.
//
// It never touches the system directly: every change goes through the daemon's
// Unix socket, which is why it can run unprivileged and still reconfigure
// routing in real time.
//
// The window is split in two: tunnels on the left, rules on the right. Dropping
// a rule onto a tunnel reassigns it, which is the whole point of the layout.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/diamondburned/gotk4-adwaita/pkg/adw"
	coreglib "github.com/diamondburned/gotk4/pkg/core/glib"
	"github.com/diamondburned/gotk4/pkg/gdk/v4"
	"github.com/diamondburned/gotk4/pkg/gio/v2"
	"github.com/diamondburned/gotk4/pkg/glib/v2"
	"github.com/diamondburned/gotk4/pkg/gtk/v4"

	"github.com/maks/dual-vpn-router/internal/api"
	"github.com/maks/dual-vpn-router/internal/config"
	"github.com/maks/dual-vpn-router/internal/engine"
)

const appID = "io.github.maks.DualVpnRouter"

// refreshInterval keeps the window in step with tunnels that go up or down
// outside the app, such as NetworkManager reconnecting on its own.
const refreshInterval = 3

// callTimeout is generous because bringing a VPN up can take tens of seconds.
const callTimeout = 90 * time.Second

// Drag payloads are strings because GTK's string content type needs no custom
// GType registration. The prefix says which list the row came from.
const (
	dragRule = "rule:"
	dragDNS  = "dns:"
)

const styles = `
.dvpn-drop-hover {
  background-color: alpha(@accent_bg_color, 0.30);
  outline: 2px solid @accent_bg_color;
  outline-offset: -2px;
}
.dvpn-dragging { opacity: 0.35; }
.dvpn-pane-title {
  font-weight: bold;
  margin: 12px 4px 6px 4px;
}
`

func main() {
	socket := api.DefaultSocket
	if v := os.Getenv("DUAL_VPN_SOCKET"); v != "" {
		socket = v
	}

	app := adw.NewApplication(appID, gio.ApplicationFlagsNone)
	u := &ui{client: api.NewClient(socket)}

	app.ConnectActivate(func() { u.activate(app) })

	if code := app.Run(os.Args); code > 0 {
		os.Exit(code)
	}
}

type ui struct {
	client *api.Client

	win    *adw.ApplicationWindow
	toasts *adw.ToastOverlay
	banner *adw.Banner

	masterSwitch *gtk.Switch

	vpnList  *gtk.ListBox
	ruleList *gtk.ListBox
	dnsList  *gtk.ListBox

	tunnelRows map[string]*tunnelRow
	ruleRows   map[string]*ruleRow
	dnsRows    map[string]*dnsRow

	// state is the last snapshot from the daemon. A DNS drop needs it because
	// the only way to change "via" is to re-send the whole rule.
	state engine.State

	// signature tracks which entries exist, so rows are rebuilt only when the
	// set changes rather than on every poll.
	signature string

	// updating suppresses widget callbacks while values are set programmatically.
	updating bool
	inFlight bool
}

type tunnelRow struct {
	row  *adw.ActionRow
	dot  *gtk.Image
	sw   *gtk.Switch
	dele *gtk.Button
}

type ruleRow struct {
	row *adw.ActionRow
	sw  *gtk.Switch
}

type dnsRow struct {
	row *adw.ActionRow
	sw  *gtk.Switch
}

func (u *ui) activate(app *adw.Application) {
	u.tunnelRows = map[string]*tunnelRow{}
	u.ruleRows = map[string]*ruleRow{}
	u.dnsRows = map[string]*dnsRow{}

	if d := gdk.DisplayGetDefault(); d != nil {
		p := gtk.NewCSSProvider()
		p.LoadFromData(styles)
		gtk.StyleContextAddProviderForDisplay(d, p, gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
	}

	u.win = adw.NewApplicationWindow(&app.Application)
	u.win.SetTitle("Dual VPN Router")
	u.win.SetDefaultSize(940, 700)

	header := adw.NewHeaderBar()
	header.PackStart(u.buildMasterSwitch())

	refresh := gtk.NewButtonFromIconName("view-refresh-symbolic")
	refresh.SetTooltipText("Обновить")
	refresh.ConnectClicked(func() { u.refresh() })
	header.PackEnd(refresh)

	u.banner = adw.NewBanner("")
	u.banner.SetRevealed(false)
	// Banners parse Pango markup by default, and daemon errors are arbitrary text.
	u.banner.SetUseMarkup(false)

	paned := gtk.NewPaned(gtk.OrientationHorizontal)
	paned.SetStartChild(u.buildVPNPane())
	paned.SetEndChild(u.buildRulePane())
	paned.SetPosition(320)
	paned.SetResizeStartChild(false)
	paned.SetVExpand(true)

	content := gtk.NewBox(gtk.OrientationVertical, 0)
	content.Append(u.banner)
	content.Append(paned)

	toolbar := adw.NewToolbarView()
	toolbar.AddTopBar(header)
	toolbar.SetContent(content)

	u.toasts = adw.NewToastOverlay()
	u.toasts.SetChild(toolbar)

	u.win.SetContent(u.toasts)
	u.win.Present()

	u.refresh()
	glib.TimeoutSecondsAdd(refreshInterval, func() bool {
		u.refresh()
		return true
	})
}

func (u *ui) buildMasterSwitch() *gtk.Box {
	box := gtk.NewBox(gtk.OrientationHorizontal, 8)

	label := gtk.NewLabel("Маршрутизация")
	u.masterSwitch = gtk.NewSwitch()
	u.masterSwitch.SetVAlign(gtk.AlignCenter)
	u.masterSwitch.SetTooltipText("Применить или снять все правила")
	u.masterSwitch.ConnectStateSet(func(state bool) bool {
		if u.updating {
			return false
		}
		if state {
			u.call(func(ctx context.Context) (engine.State, error) { return u.client.Start(ctx) })
		} else {
			u.call(func(ctx context.Context) (engine.State, error) { return u.client.Stop(ctx) })
		}
		return false
	})

	box.Append(label)
	box.Append(u.masterSwitch)
	return box
}

// buildVPNPane builds the left-hand list. Every row in it is a drop target.
func (u *ui) buildVPNPane() *gtk.Widget {
	box := gtk.NewBox(gtk.OrientationVertical, 0)
	box.SetMarginTop(6)
	box.SetMarginStart(12)
	box.SetMarginEnd(6)
	box.SetMarginBottom(12)

	title := gtk.NewLabel("VPN")
	title.SetXAlign(0)
	title.AddCSSClass("dvpn-pane-title")
	box.Append(title)

	hint := gtk.NewLabel("Перетащите правило сюда, чтобы направить его в этот туннель")
	hint.SetXAlign(0)
	hint.SetWrap(true)
	hint.AddCSSClass("dim-label")
	hint.AddCSSClass("caption")
	hint.SetMarginBottom(6)
	box.Append(hint)

	u.vpnList = gtk.NewListBox()
	u.vpnList.SetSelectionMode(gtk.SelectionNone)
	u.vpnList.AddCSSClass("boxed-list")

	scroll := gtk.NewScrolledWindow()
	scroll.SetChild(u.vpnList)
	scroll.SetVExpand(true)
	scroll.SetPolicy(gtk.PolicyNever, gtk.PolicyAutomatic)
	box.Append(scroll)

	add := gtk.NewButtonWithLabel("Добавить VPN")
	add.SetMarginTop(8)
	add.ConnectClicked(u.showAddTunnelDialog)
	box.Append(add)

	return &box.Widget
}

// buildRulePane builds the right-hand lists. Every row in them is a drag source.
func (u *ui) buildRulePane() *gtk.Widget {
	box := gtk.NewBox(gtk.OrientationVertical, 0)
	box.SetMarginTop(6)
	box.SetMarginStart(6)
	box.SetMarginEnd(12)
	box.SetMarginBottom(12)

	u.ruleList = gtk.NewListBox()
	u.ruleList.SetSelectionMode(gtk.SelectionNone)
	u.ruleList.AddCSSClass("boxed-list")

	u.dnsList = gtk.NewListBox()
	u.dnsList.SetSelectionMode(gtk.SelectionNone)
	u.dnsList.AddCSSClass("boxed-list")

	box.Append(paneHeading("Маршруты", "Добавить маршрут", u.showAddRuleDialog))
	box.Append(u.ruleList)
	box.Append(paneHeading("DNS", "Добавить домен", u.showAddDNSDialog))
	box.Append(u.dnsList)

	scroll := gtk.NewScrolledWindow()
	scroll.SetChild(box)
	scroll.SetVExpand(true)
	scroll.SetPolicy(gtk.PolicyNever, gtk.PolicyAutomatic)
	return &scroll.Widget
}

func paneHeading(text, tooltip string, onAdd func()) *gtk.Box {
	row := gtk.NewBox(gtk.OrientationHorizontal, 6)

	label := gtk.NewLabel(text)
	label.SetXAlign(0)
	label.SetHExpand(true)
	label.AddCSSClass("dvpn-pane-title")

	add := gtk.NewButtonFromIconName("list-add-symbolic")
	add.SetTooltipText(tooltip)
	add.AddCSSClass("flat")
	add.SetVAlign(gtk.AlignCenter)
	add.ConnectClicked(onAdd)

	row.Append(label)
	row.Append(add)
	return row
}

// call runs a daemon request off the UI thread and applies the resulting state
// back on it. Every daemon method returns the new state, so one round trip is
// enough to both act and refresh.
func (u *ui) call(fn func(context.Context) (engine.State, error)) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()

		st, err := fn(ctx)
		glib.IdleAdd(func() {
			if err != nil {
				u.showError(err)
				return
			}
			u.render(st)
		})
	}()
}

// refresh polls state, skipping the poll if one is already outstanding so a
// slow daemon cannot queue up requests.
func (u *ui) refresh() {
	if u.inFlight {
		return
	}
	u.inFlight = true

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()

		st, err := u.client.State(ctx)
		glib.IdleAdd(func() {
			u.inFlight = false
			if err != nil {
				u.showDisconnected(err)
				return
			}
			u.render(st)
		})
	}()
}

func (u *ui) showDisconnected(err error) {
	msg := "Демон недоступен. Запустите его: sudo systemctl start dual-vpn"
	if strings.Contains(err.Error(), "permission denied") {
		msg = "Нет доступа к управляющему сокету. Добавьте себя в группу dual-vpn и перезайдите в сессию."
	}
	u.banner.SetTitle(msg)
	u.banner.SetRevealed(true)
}

func (u *ui) showError(err error) {
	u.toasts.AddToast(adw.NewToast(err.Error()))
	u.refresh()
}

func (u *ui) render(st engine.State) {
	u.state = st

	u.banner.SetRevealed(st.LastError != "")
	if st.LastError != "" {
		u.banner.SetTitle(st.LastError)
	}

	sig := signatureOf(st)
	if sig != u.signature {
		u.signature = sig
		u.rebuild(st)
	}

	u.updating = true
	defer func() { u.updating = false }()

	u.masterSwitch.SetActive(st.Active)

	for _, t := range st.Tunnels {
		r, ok := u.tunnelRows[t.Name]
		if !ok {
			continue
		}
		r.row.SetSubtitle(tunnelSubtitle(t))
		r.sw.SetActive(t.Up)
		// A manual tunnel is observed, not driven, so its switch is inert.
		r.sw.SetSensitive(t.Managed)
		setDot(r.dot, t.Up)
	}

	for _, rule := range st.Rules {
		r, ok := u.ruleRows[rule.ID]
		if !ok {
			continue
		}
		r.row.SetSubtitle(ruleSubtitle(rule))
		r.sw.SetActive(rule.Enabled)
	}

	for _, d := range st.DNSRules {
		r, ok := u.dnsRows[d.Domain]
		if !ok {
			continue
		}
		r.row.SetSubtitle(dnsSubtitle(d))
		r.sw.SetActive(d.Enabled)
	}
}

// signatureOf changes whenever an entry is added or removed, which is the only
// time the rows need rebuilding.
func signatureOf(st engine.State) string {
	var b strings.Builder
	for _, t := range st.Tunnels {
		b.WriteString("t:" + t.Name + ";")
	}
	for _, r := range st.Rules {
		b.WriteString("r:" + r.ID + ";")
	}
	for _, d := range st.DNSRules {
		b.WriteString("d:" + d.Domain + ";")
	}
	return b.String()
}

func (u *ui) rebuild(st engine.State) {
	u.vpnList.RemoveAll()
	u.ruleList.RemoveAll()
	u.dnsList.RemoveAll()

	u.tunnelRows = map[string]*tunnelRow{}
	u.ruleRows = map[string]*ruleRow{}
	u.dnsRows = map[string]*dnsRow{}

	for _, t := range st.Tunnels {
		u.vpnList.Append(u.newTunnelRow(t))
	}
	u.vpnList.Append(u.newDirectRow())

	for _, r := range st.Rules {
		u.ruleList.Append(u.newRuleRow(r))
	}
	for _, d := range st.DNSRules {
		u.dnsList.Append(u.newDNSRow(d))
	}
}

func setDot(dot *gtk.Image, up bool) {
	if up {
		dot.RemoveCSSClass("dim-label")
		dot.AddCSSClass("success")
	} else {
		dot.RemoveCSSClass("success")
		dot.AddCSSClass("dim-label")
	}
}

func (u *ui) newTunnelRow(t engine.TunnelView) *adw.ActionRow {
	name := t.Name

	dot := gtk.NewImageFromIconName("media-record-symbolic")
	setDot(dot, t.Up)

	sw := gtk.NewSwitch()
	sw.SetVAlign(gtk.AlignCenter)
	sw.SetSensitive(t.Managed)
	sw.ConnectStateSet(func(state bool) bool {
		if u.updating {
			return false
		}
		u.call(func(ctx context.Context) (engine.State, error) {
			return u.client.SetTunnel(ctx, name, state)
		})
		return false
	})

	del := gtk.NewButtonFromIconName("user-trash-symbolic")
	del.SetTooltipText("Удалить туннель")
	del.AddCSSClass("flat")
	del.SetVAlign(gtk.AlignCenter)
	del.ConnectClicked(func() {
		u.confirm("Удалить туннель?",
			fmt.Sprintf("Туннель %q будет убран из конфигурации. Сначала переназначьте его правила.", name),
			func() {
				u.call(func(ctx context.Context) (engine.State, error) {
					return u.client.DeleteTunnel(ctx, name)
				})
			})
	})

	row := adw.NewActionRow()
	row.SetTitle(t.Name)
	row.SetSubtitle(tunnelSubtitle(t))
	row.AddPrefix(dot)
	row.AddSuffix(sw)
	row.AddSuffix(del)

	u.attachDropTarget(row, name)

	u.tunnelRows[t.Name] = &tunnelRow{row: row, dot: dot, sw: sw, dele: del}
	return row
}

// newDirectRow gives the user somewhere to drop a rule to take it off a tunnel.
func (u *ui) newDirectRow() *adw.ActionRow {
	icon := gtk.NewImageFromIconName("go-jump-symbolic")

	row := adw.NewActionRow()
	row.SetTitle("Напрямую")
	row.SetSubtitle("без туннеля, по обычному маршруту")
	row.AddPrefix(icon)

	u.attachDropTarget(row, config.TargetDirect)
	return row
}

func (u *ui) newRuleRow(r engine.RuleView) *adw.ActionRow {
	id := r.ID

	sw := gtk.NewSwitch()
	sw.SetVAlign(gtk.AlignCenter)
	sw.ConnectStateSet(func(state bool) bool {
		if u.updating {
			return false
		}
		u.call(func(ctx context.Context) (engine.State, error) {
			return u.client.SetRule(ctx, id, state)
		})
		return false
	})

	del := gtk.NewButtonFromIconName("user-trash-symbolic")
	del.SetTooltipText("Удалить правило")
	del.AddCSSClass("flat")
	del.SetVAlign(gtk.AlignCenter)
	del.ConnectClicked(func() {
		u.confirm("Удалить правило?", fmt.Sprintf("Правило %q будет убрано из конфигурации.", id), func() {
			u.call(func(ctx context.Context) (engine.State, error) {
				return u.client.DeleteRule(ctx, id)
			})
		})
	})

	row := adw.NewActionRow()
	row.SetTitle(r.ID)
	row.SetSubtitle(ruleSubtitle(r))
	row.AddPrefix(dragHandle())
	row.AddSuffix(sw)
	row.AddSuffix(del)

	attachDragSource(row, dragRule+id)

	u.ruleRows[r.ID] = &ruleRow{row: row, sw: sw}
	return row
}

func (u *ui) newDNSRow(d engine.DNSRuleView) *adw.ActionRow {
	domain := d.Domain

	sw := gtk.NewSwitch()
	sw.SetVAlign(gtk.AlignCenter)
	sw.ConnectStateSet(func(state bool) bool {
		if u.updating {
			return false
		}
		u.call(func(ctx context.Context) (engine.State, error) {
			return u.client.SetDNSRule(ctx, domain, state)
		})
		return false
	})

	del := gtk.NewButtonFromIconName("user-trash-symbolic")
	del.SetTooltipText("Удалить домен")
	del.AddCSSClass("flat")
	del.SetVAlign(gtk.AlignCenter)
	del.ConnectClicked(func() {
		u.confirm("Удалить домен?", fmt.Sprintf("%s будет резолвиться через запасные серверы.", domain), func() {
			u.call(func(ctx context.Context) (engine.State, error) {
				return u.client.DeleteDNSRule(ctx, domain)
			})
		})
	})

	row := adw.NewActionRow()
	row.SetTitle(d.Domain)
	row.SetSubtitle(dnsSubtitle(d))
	row.AddPrefix(dragHandle())
	row.AddSuffix(sw)
	row.AddSuffix(del)

	attachDragSource(row, dragDNS+domain)

	u.dnsRows[d.Domain] = &dnsRow{row: row, sw: sw}
	return row
}

func dragHandle() *gtk.Image {
	img := gtk.NewImageFromIconName("list-drag-handle-symbolic")
	img.AddCSSClass("dim-label")
	img.SetTooltipText("Перетащите на VPN слева")
	return img
}

func attachDragSource(row *adw.ActionRow, payload string) {
	src := gtk.NewDragSource()
	src.SetActions(gdk.ActionCopy)
	src.ConnectPrepare(func(x, y float64) *gdk.ContentProvider {
		return gdk.NewContentProviderForValue(coreglib.NewValue(payload))
	})
	src.ConnectDragBegin(func(gdk.Dragger) {
		src.SetIcon(gtk.NewWidgetPaintable(row), 0, 0)
		row.AddCSSClass("dvpn-dragging")
	})
	src.ConnectDragEnd(func(gdk.Dragger, bool) {
		row.RemoveCSSClass("dvpn-dragging")
	})
	row.AddController(src)
}

func (u *ui) attachDropTarget(row *adw.ActionRow, target string) {
	dst := gtk.NewDropTarget(coreglib.TypeString, gdk.ActionCopy)
	dst.ConnectEnter(func(x, y float64) gdk.DragAction {
		row.AddCSSClass("dvpn-drop-hover")
		return gdk.ActionCopy
	})
	dst.ConnectLeave(func() {
		row.RemoveCSSClass("dvpn-drop-hover")
	})
	dst.ConnectDrop(func(value *coreglib.Value, x, y float64) bool {
		row.RemoveCSSClass("dvpn-drop-hover")
		return u.handleDrop(value.String(), target)
	})
	row.AddController(dst)
}

// handleDrop reassigns whatever was dragged onto the tunnel named target.
func (u *ui) handleDrop(payload, target string) bool {
	switch {
	case strings.HasPrefix(payload, dragRule):
		id := strings.TrimPrefix(payload, dragRule)
		u.call(func(ctx context.Context) (engine.State, error) {
			return u.client.SetRuleTarget(ctx, id, target)
		})
		return true

	case strings.HasPrefix(payload, dragDNS):
		domain := strings.TrimPrefix(payload, dragDNS)
		for _, d := range u.state.DNSRules {
			if d.Domain != domain {
				continue
			}
			// The API has no "set via", so the rule is re-sent whole.
			via := target
			if target == config.TargetDirect {
				via = ""
			}
			updated := config.DNSRule{
				Domain:  d.Domain,
				Servers: d.Servers,
				Via:     via,
				Enabled: d.Enabled,
			}
			u.call(func(ctx context.Context) (engine.State, error) {
				return u.client.UpsertDNSRule(ctx, updated)
			})
			return true
		}
	}
	return false
}

func tunnelSubtitle(t engine.TunnelView) string {
	kind := string(t.Kind)
	// Spelling this one out explains why the row's switch is greyed out.
	if t.Kind == config.KindManual {
		kind = "только наблюдение"
	}
	parts := []string{kind}
	if t.Profile != "" {
		parts = append(parts, t.Profile)
	}
	if t.Interface != "" {
		parts = append(parts, t.Interface)
	}
	switch {
	case t.Up:
		if t.Gateway != "" {
			parts = append(parts, "поднят, шлюз "+t.Gateway)
		} else {
			parts = append(parts, "поднят")
		}
	case t.Present:
		parts = append(parts, "есть, но опущен")
	default:
		parts = append(parts, "не подключён")
	}
	if t.Detail != "" {
		parts = append(parts, t.Detail)
	}
	return strings.Join(parts, " · ")
}

func ruleSubtitle(r engine.RuleView) string {
	s := strings.Join(r.CIDRs, ", ")
	s += "  →  " + targetLabel(r.Target)
	if r.Reason != "" {
		s += " · " + r.Reason
	} else if r.Applied {
		s += " · действует"
	}
	return s
}

func dnsSubtitle(d engine.DNSRuleView) string {
	s := strings.Join(d.Servers, ", ")
	s += "  →  " + targetLabel(d.Via)
	if d.Reason != "" {
		s += " · " + d.Reason
	} else if d.Applied {
		s += " · действует"
	}
	return s
}

func targetLabel(target string) string {
	if target == "" || target == config.TargetDirect {
		return "напрямую"
	}
	return target
}

func (u *ui) confirm(heading, body string, onConfirm func()) {
	dlg := adw.NewMessageDialog(&u.win.ApplicationWindow.Window, heading, body)
	dlg.AddResponse("cancel", "Отмена")
	dlg.AddResponse("delete", "Удалить")
	dlg.SetResponseAppearance("delete", adw.ResponseDestructive)
	dlg.SetDefaultResponse("cancel")
	dlg.ConnectResponse(func(response string) {
		if response == "delete" {
			onConfirm()
		}
	})
	dlg.Present()
}

// entryRow builds a labelled text field for the add dialogs.
func entryRow(box *gtk.Box, label, placeholder string) *gtk.Entry {
	l := gtk.NewLabel(label)
	l.SetXAlign(0)
	l.AddCSSClass("dim-label")

	e := gtk.NewEntry()
	e.SetPlaceholderText(placeholder)

	box.Append(l)
	box.Append(e)
	return e
}

func dropDownRow(box *gtk.Box, label string, items []string) *gtk.DropDown {
	l := gtk.NewLabel(label)
	l.SetXAlign(0)
	l.AddCSSClass("dim-label")

	dd := gtk.NewDropDownFromStrings(items)

	box.Append(l)
	box.Append(dd)
	return dd
}

func (u *ui) tunnelNames() []string {
	out := make([]string, 0, len(u.state.Tunnels))
	for _, t := range u.state.Tunnels {
		out = append(out, t.Name)
	}
	return out
}

// showAddTunnelDialog offers the profiles the host already has, so the user
// picks from a list instead of typing a name that has to match exactly.
func (u *ui) showAddTunnelDialog() {
	u.fetchProfiles(func(p api.Profiles, err error) {
		if err != nil {
			u.showError(err)
			return
		}
		u.presentAddTunnelDialog(p)
	})
}

// fetchProfiles re-reads both the host profiles and the current state, because
// which profiles are still free depends on the tunnels that exist right now.
func (u *ui) fetchProfiles(done func(api.Profiles, error)) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()

		profiles, err := u.client.Profiles(ctx)
		st, stErr := u.client.State(ctx)
		glib.IdleAdd(func() {
			if err == nil && stErr == nil {
				u.render(st)
			}
			done(profiles, err)
		})
	}()
}

// candidate is one discovered profile. takenBy names the tunnel already using
// it, which keeps the profile on screen instead of silently vanishing.
type candidate struct {
	title    string
	subtitle string
	profile  string
	iface    string
	kind     config.TunnelKind
	takenBy  string
}

func candidatesFrom(p api.Profiles, st engine.State) []candidate {
	taken := map[string]string{}
	for _, t := range st.Tunnels {
		taken[string(t.Kind)+"/"+t.Profile] = t.Name
	}
	// A manual tunnel is identified by its device, not by a profile name.
	takenIface := map[string]string{}
	for _, t := range st.Tunnels {
		if t.Interface != "" {
			takenIface[t.Interface] = t.Name
		}
	}

	var out []candidate
	for _, nm := range p.NetworkManager {
		subtitle := "NetworkManager · " + nm.Type
		if nm.Active {
			subtitle += " · активен"
		}
		out = append(out, candidate{
			title:    nm.Name,
			subtitle: subtitle,
			profile:  nm.Name,
			kind:     config.KindNM,
			takenBy:  taken[string(config.KindNM)+"/"+nm.Name],
		})
	}
	for _, wg := range p.WireGuard {
		out = append(out, candidate{
			title:    wg,
			subtitle: "WireGuard · /etc/wireguard/" + wg + ".conf",
			profile:  wg,
			kind:     config.KindWGQuick,
			takenBy:  taken[string(config.KindWGQuick)+"/"+wg],
		})
	}
	for _, awg := range p.Amnezia {
		out = append(out, candidate{
			title:    awg,
			subtitle: "AmneziaWG · " + config.AmneziaDir + "/" + awg + ".conf",
			profile:  awg,
			kind:     config.KindAWGQuick,
			takenBy:  taken[string(config.KindAWGQuick)+"/"+awg],
		})
	}
	for _, iface := range p.Interfaces {
		// A device that a profile above already drives would be a duplicate.
		if profileDrives(p, iface.Name) {
			continue
		}
		subtitle := "Интерфейс · только наблюдение"
		if iface.Up {
			subtitle += " · поднят"
		}
		if len(iface.Addresses) > 0 {
			subtitle += " · " + strings.Join(iface.Addresses, ", ")
		}
		out = append(out, candidate{
			title:    iface.Name,
			subtitle: subtitle,
			iface:    iface.Name,
			kind:     config.KindManual,
			takenBy:  takenIface[iface.Name],
		})
	}
	return out
}

// defaultName seeds the tunnel name from whichever identifier the candidate has.
func (c candidate) defaultName() string {
	if c.profile != "" {
		return c.profile
	}
	return c.iface
}

// profileDrives reports whether a NetworkManager or wg-quick profile already
// owns this device, so it is not offered a second time as a manual tunnel.
func profileDrives(p api.Profiles, iface string) bool {
	for _, nm := range p.NetworkManager {
		if nm.Device == iface {
			return true
		}
	}
	// Both wg-quick flavours name the interface after the config file.
	for _, wg := range p.WireGuard {
		if wg == iface {
			return true
		}
	}
	for _, awg := range p.Amnezia {
		if awg == iface {
			return true
		}
	}
	return false
}

func (u *ui) presentAddTunnelDialog(p api.Profiles) {
	box := gtk.NewBox(gtk.OrientationVertical, 6)

	caption := gtk.NewLabel("Найденные профили")
	caption.SetXAlign(0)
	caption.SetHExpand(true)
	caption.AddCSSClass("dim-label")

	reload := gtk.NewButtonFromIconName("view-refresh-symbolic")
	reload.SetTooltipText("Перечитать профили с машины")
	reload.AddCSSClass("flat")
	reload.SetVAlign(gtk.AlignCenter)

	head := gtk.NewBox(gtk.OrientationHorizontal, 6)
	head.Append(caption)
	head.Append(reload)
	box.Append(head)

	empty := gtk.NewLabel("Ничего не найдено. Создайте подключение в настройках сети, " +
		"положите конфиг в /etc/wireguard или поднимите VPN любым другим способом — " +
		"его интерфейс появится здесь. Затем нажмите «Обновить».")
	empty.SetWrap(true)
	empty.SetXAlign(0)
	box.Append(empty)

	list := gtk.NewListBox()
	list.SetSelectionMode(gtk.SelectionSingle)
	list.AddCSSClass("boxed-list")

	scroll := gtk.NewScrolledWindow()
	scroll.SetChild(list)
	scroll.SetPolicy(gtk.PolicyNever, gtk.PolicyAutomatic)
	scroll.SetMinContentHeight(280)
	scroll.SetVExpand(true)
	box.Append(scroll)

	nameEntry := entryRow(box, "Имя туннеля", "например, work")

	dlg := adw.NewMessageDialog(&u.win.ApplicationWindow.Window, "Добавить VPN", "")
	dlg.SetExtraChild(box)
	dlg.AddResponse("cancel", "Отмена")
	dlg.AddResponse("add", "Добавить")
	dlg.SetResponseAppearance("add", adw.ResponseSuggested)
	dlg.SetDefaultResponse("add")

	var cands []candidate

	// Keep the name in step with the pick until the user types their own.
	edited := false
	nameEntry.ConnectChanged(func() {
		if !u.updating {
			edited = true
		}
	})

	selected := func() (candidate, bool) {
		row := list.SelectedRow()
		if row == nil {
			return candidate{}, false
		}
		i := row.Index()
		if i < 0 || i >= len(cands) || cands[i].takenBy != "" {
			return candidate{}, false
		}
		return cands[i], true
	}

	list.ConnectRowSelected(func(*gtk.ListBoxRow) {
		c, ok := selected()
		dlg.SetResponseEnabled("add", ok)
		if !ok || edited {
			return
		}
		u.updating = true
		nameEntry.SetText(c.defaultName())
		u.updating = false
	})

	fill := func(p api.Profiles) {
		cands = candidatesFrom(p, u.state)
		list.RemoveAll()
		for _, c := range cands {
			row := adw.NewActionRow()
			row.SetTitle(c.title)
			row.SetSubtitle(c.subtitle)
			if c.takenBy != "" {
				row.SetSubtitle(c.subtitle + " · уже добавлен как «" + c.takenBy + "»")
				row.SetSensitive(false)
			}
			list.Append(row)
		}

		empty.SetVisible(len(cands) == 0)
		scroll.SetVisible(len(cands) > 0)

		dlg.SetResponseEnabled("add", false)
		for i, c := range cands {
			if c.takenBy == "" {
				list.SelectRow(list.RowAtIndex(i))
				break
			}
		}
	}
	fill(p)

	reload.ConnectClicked(func() {
		reload.SetSensitive(false)
		u.fetchProfiles(func(p api.Profiles, err error) {
			reload.SetSensitive(true)
			if err != nil {
				u.showError(err)
				return
			}
			fill(p)
		})
	})

	dlg.ConnectResponse(func(response string) {
		if response != "add" {
			return
		}
		c, ok := selected()
		if !ok {
			return
		}
		name := strings.TrimSpace(nameEntry.Text())
		if name == "" {
			name = c.defaultName()
		}
		// TableID is left at zero so the daemon picks a free routing table.
		// AutoDetect stays off: every candidate names either a profile or a
		// device, and guessing would bind the tunnel to somebody else's VPN.
		tunnel := config.Tunnel{
			Name:      name,
			Kind:      c.kind,
			Profile:   c.profile,
			Interface: c.iface,
		}
		u.call(func(ctx context.Context) (engine.State, error) {
			return u.client.UpsertTunnel(ctx, tunnel)
		})
	})
	dlg.Present()
}

func (u *ui) showAddRuleDialog() {
	box := gtk.NewBox(gtk.OrientationVertical, 6)
	idEntry := entryRow(box, "Название правила", "corp-networks")
	cidrEntry := entryRow(box, "Назначения через запятую", "10.0.0.0/8, 172.16.0.0/12")

	targets := append([]string{config.TargetDirect}, u.tunnelNames()...)
	targetDD := dropDownRow(box, "Направить через", targets)

	failClosed := gtk.NewCheckButtonWithLabel("Блокировать этот трафик, пока туннель опущен")
	box.Append(failClosed)

	dlg := adw.NewMessageDialog(&u.win.ApplicationWindow.Window, "Новый маршрут", "")
	dlg.SetExtraChild(box)
	dlg.AddResponse("cancel", "Отмена")
	dlg.AddResponse("add", "Добавить")
	dlg.SetResponseAppearance("add", adw.ResponseSuggested)
	dlg.SetDefaultResponse("add")
	dlg.ConnectResponse(func(response string) {
		if response != "add" {
			return
		}
		sel := int(targetDD.Selected())
		if sel < 0 || sel >= len(targets) {
			return
		}
		rule := config.Rule{
			ID:         strings.TrimSpace(idEntry.Text()),
			Target:     targets[sel],
			CIDRs:      splitList(cidrEntry.Text()),
			Enabled:    true,
			FailClosed: failClosed.Active(),
		}
		u.call(func(ctx context.Context) (engine.State, error) {
			return u.client.UpsertRule(ctx, rule)
		})
	})
	dlg.Present()
}

func (u *ui) showAddDNSDialog() {
	box := gtk.NewBox(gtk.OrientationVertical, 6)
	domainEntry := entryRow(box, "Домен", "itlabs.io")
	serverEntry := entryRow(box, "DNS-серверы через запятую", "10.0.16.1, 10.2.16.1")

	// An empty "via" is valid and means the query is not pinned to a tunnel.
	names := u.tunnelNames()
	vias := append([]string{""}, names...)
	display := append([]string{"напрямую"}, names...)
	viaDD := dropDownRow(box, "Ходить к этим серверам через", display)

	dlg := adw.NewMessageDialog(&u.win.ApplicationWindow.Window, "Новый домен", "")
	dlg.SetExtraChild(box)
	dlg.AddResponse("cancel", "Отмена")
	dlg.AddResponse("add", "Добавить")
	dlg.SetResponseAppearance("add", adw.ResponseSuggested)
	dlg.SetDefaultResponse("add")
	dlg.ConnectResponse(func(response string) {
		if response != "add" {
			return
		}
		sel := int(viaDD.Selected())
		if sel < 0 || sel >= len(vias) {
			return
		}
		rule := config.DNSRule{
			Domain:  strings.TrimSpace(domainEntry.Text()),
			Servers: splitList(serverEntry.Text()),
			Via:     vias[sel],
			Enabled: true,
		}
		u.call(func(ctx context.Context) (engine.State, error) {
			return u.client.UpsertDNSRule(ctx, rule)
		})
	})
	dlg.Present()
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}
