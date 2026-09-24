#!/usr/bin/env bash
#
# Installs the dual-vpn daemon and GUI.
#
# The daemon runs as root because routing and DNS require it. The control
# socket is owned by the dual-vpn group so the desktop GUI can toggle routes
# without prompting for a password every time.
#
# Usage: sudo ./packaging/install.sh

set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
GROUP="dual-vpn"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $EUID -ne 0 ]]; then
    echo "error: run this with sudo" >&2
    exit 1
fi

# The user who invoked sudo is the one who needs group membership.
TARGET_USER="${SUDO_USER:-}"
if [[ -z "$TARGET_USER" ]]; then
    echo "error: could not determine the desktop user; run via sudo, not as root directly" >&2
    exit 1
fi

echo "==> Checking build dependencies"
missing=()
command -v go >/dev/null || missing+=("golang-go")
pkg-config --exists gtk4 2>/dev/null || missing+=("libgtk-4-dev")
pkg-config --exists libadwaita-1 2>/dev/null || missing+=("libadwaita-1-dev")
# gotk4's cgo bindings pull in gobject-introspection headers, which libgtk-4-dev
# does not depend on.
pkg-config --exists gobject-introspection-1.0 2>/dev/null || missing+=("libgirepository1.0-dev")
command -v dnsmasq >/dev/null || missing+=("dnsmasq")

if (( ${#missing[@]} )); then
    echo "error: missing packages: ${missing[*]}" >&2
    echo "install them with: sudo apt install ${missing[*]}" >&2
    exit 1
fi

echo "==> Building binaries"
cd "$REPO_ROOT"
# Build as the invoking user so the module cache does not end up root-owned.
sudo -u "$TARGET_USER" env PATH="$PATH" go build -o dual-vpn ./cmd/dual-vpn
sudo -u "$TARGET_USER" env PATH="$PATH" go build -o dual-vpn-gui ./cmd/dual-vpn-gui

echo "==> Installing to $BINDIR"
install -Dm755 dual-vpn "$BINDIR/dual-vpn"
install -Dm755 dual-vpn-gui "$BINDIR/dual-vpn-gui"

echo "==> Creating the $GROUP group"
if ! getent group "$GROUP" >/dev/null; then
    groupadd --system "$GROUP"
fi
if ! id -nG "$TARGET_USER" | tr ' ' '\n' | grep -qx "$GROUP"; then
    usermod -aG "$GROUP" "$TARGET_USER"
    NEEDS_RELOGIN=1
fi

echo "==> Installing the default configuration"
if [[ ! -f /etc/dual-vpn/config.yaml ]]; then
    install -d -m 0755 /etc/dual-vpn
    "$BINDIR/dual-vpn" init
else
    echo "    /etc/dual-vpn/config.yaml already exists, leaving it alone"
fi

echo "==> Installing the systemd unit"
install -Dm644 packaging/dual-vpn.service /etc/systemd/system/dual-vpn.service
systemctl daemon-reload
systemctl enable --now dual-vpn.service

echo "==> Installing the desktop entry"
install -Dm644 packaging/dual-vpn-gui.desktop /usr/share/applications/dual-vpn-gui.desktop
update-desktop-database /usr/share/applications 2>/dev/null || true

echo
echo "Done."
echo "  Daemon:  systemctl status dual-vpn"
echo "  CLI:     dual-vpn status"
echo "  GUI:     dual-vpn-gui  (also in your app grid as \"Dual VPN Router\")"
if [[ -n "${NEEDS_RELOGIN:-}" ]]; then
    echo
    echo "NOTE: $TARGET_USER was added to the $GROUP group."
    echo "      Log out and back in before the GUI can reach the daemon."
fi
