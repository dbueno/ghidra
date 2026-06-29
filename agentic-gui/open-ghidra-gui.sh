#!/usr/bin/env bash
# Launch the agentic Ghidra into the macOS *Aqua* (desktop) session.
#
# Why this exists: a JVM started from a background/non-GUI shell on macOS is
# headless and cannot create windows. macOS only grants a desktop session to
# processes launched through LaunchServices (`open`). So we wrap the launcher in
# a tiny .app bundle and `open` it -- the resulting Ghidra JVM gets a real
# display, and its in-JVM bridge is then reachable over 127.0.0.1 from anywhere
# on the machine (including an automation agent's shell).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
PORT="${GUI_BRIDGE_PORT:-18217}"
APP="$ROOT/agentic-gui/build/GhidraAgentic.app"
NIX_SHELL="$(command -v nix-shell)"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>GhidraAgentic</string>
  <key>CFBundleIdentifier</key><string>local.ghidra.agentic</string>
  <key>CFBundleExecutable</key><string>run</string>
  <key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>
PLIST
cat > "$APP/Contents/MacOS/run" <<RUN
#!/bin/bash
export GUI_BRIDGE_PORT=${PORT}
cd "${ROOT}"
exec "${NIX_SHELL}" "${ROOT}/shell.nix" --run "${ROOT}/run-ghidra-agentic.sh" \
  > "${ROOT}/agentic-gui/build/ghidra-launch.log" 2>&1
RUN
chmod +x "$APP/Contents/MacOS/run"

echo "==> opening $APP in the desktop session"
open "$APP"
echo "==> Ghidra is starting in your GUI session."
echo "    Bridge will come up on http://127.0.0.1:${PORT}"
echo "    Launch log: agentic-gui/build/ghidra-launch.log"
echo "    Drive it:   GUI_BRIDGE_PORT=${PORT} agentic-gui/ghidra-gui health"
