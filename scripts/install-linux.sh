#!/usr/bin/env bash
# Build lethe from source and install it for the current user (no root needed).
#
#   scripts/install-linux.sh             build + install to ~/.local
#   scripts/install-linux.sh uninstall   remove it again
#   PREFIX=/some/dir scripts/install-linux.sh
#
# Installs: the app (shows up in your app menu as "lethe"), plus the `lethe-relay`
# server and `lethe` terminal client in $PREFIX/bin.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
PREFIX=${PREFIX:-$HOME/.local}
BIN=$PREFIX/bin
APPS=$PREFIX/share/applications
ICONS=$PREFIX/share/icons/hicolor

if [[ ${1:-} == uninstall ]]; then
  rm -f "$BIN/lethe-app" "$BIN/lethe-relay" "$BIN/lethe" "$APPS/lethe.desktop"
  rm -f "$ICONS"/{32x32,128x128,256x256,512x512}/apps/lethe.png
  echo "lethe removed (your encrypted profile in ~/.local/share/org.lethe.messenger was kept)."
  exit 0
fi

need() { command -v "$1" >/dev/null || { echo "missing: $1 — $2"; exit 1; }; }
need cargo "install Rust (Arch: sudo pacman -S rust)"
need pkg-config "Arch: sudo pacman -S --needed base-devel"
pkg-config --exists webkit2gtk-4.1 || { echo "missing webkit2gtk-4.1 — Arch: sudo pacman -S --needed webkit2gtk-4.1"; exit 1; }

echo "==> building the relay and terminal client"
cargo build --release -q -p lethe-relay -p lethe-cli

echo "==> building the app (release builds take a few minutes)"
cd "$ROOT/app/src-tauri"
if [[ -x $HOME/.cargo/bin/cargo-tauri ]] || command -v cargo-tauri >/dev/null; then
  PATH=$HOME/.cargo/bin:$PATH cargo tauri build --no-bundle
else
  need npx "install Node.js, or run: cargo install tauri-cli --version '^2' --locked"
  npx -y @tauri-apps/cli@2 build --no-bundle
fi
cd "$ROOT"

echo "==> installing to $PREFIX"
install -Dm755 app/src-tauri/target/release/lethe-app "$BIN/lethe-app"
install -Dm755 target/release/lethe-relay "$BIN/lethe-relay"
install -Dm755 target/release/lethe "$BIN/lethe"
install -Dm644 app/src-tauri/icons/32x32.png "$ICONS/32x32/apps/lethe.png"
install -Dm644 app/src-tauri/icons/128x128.png "$ICONS/128x128/apps/lethe.png"
install -Dm644 app/src-tauri/icons/128x128@2x.png "$ICONS/256x256/apps/lethe.png"
install -Dm644 app/src-tauri/icons/icon.png "$ICONS/512x512/apps/lethe.png"
mkdir -p "$APPS"
cat >"$APPS/lethe.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=lethe
GenericName=Private messenger
Comment=Private messenger with no accounts or identifiers
Exec=$BIN/lethe-app
Icon=lethe
Terminal=false
Categories=Network;InstantMessaging;Chat;
Keywords=chat;messenger;private;encrypted;
StartupWMClass=lethe-app
DESKTOP
command -v update-desktop-database >/dev/null && update-desktop-database -q "$APPS" || true
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -qtf "$ICONS" || true

echo
echo "Done. Open \"lethe\" from your app menu, or run: $BIN/lethe-app"
case ":$PATH:" in *":$BIN:"*) ;; *) echo "Note: $BIN isn't on your PATH; add it to use lethe-relay / lethe from a terminal.";; esac
