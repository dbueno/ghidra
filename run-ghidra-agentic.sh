#!/usr/bin/env bash
# Launch the locally-built Ghidra with the GUI automation bridge attached.
#
#   nix-shell --run ./run-ghidra-agentic.sh
#
# The bridge is injected as a -javaagent via the distribution's
# support/launch.properties (VMARGS), so it loads only into the Ghidra app JVM.
# Once Ghidra is up, drive it from another shell with agentic-gui/ghidra-gui.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(pwd)"
PORT="${GUI_BRIDGE_PORT:-18217}"
AGENT_JAR="$ROOT/agentic-gui/build/ghidra-gui-bridge.jar"

# Build the agent jar if needed.
if [[ ! -f "$AGENT_JAR" ]]; then
  echo "==> building GUI bridge agent"
  "$ROOT/agentic-gui/build-agent.sh"
fi

# Locate the built distribution.
DIST="$(ls -d "$ROOT"/build/dist/ghidra_* 2>/dev/null | head -1 || true)"
if [[ -z "$DIST" ]]; then
  echo "ERROR: no distribution under build/dist. Run ./build-ghidra.sh first." >&2
  exit 1
fi
echo "==> distribution: $DIST"

# Idempotently inject the javaagent into the app JVM's VM args, and pin Ghidra's
# JDK to the Nix one (JAVA_HOME is set by the dev shell) so it doesn't depend on
# a system JDK.
PROPS="$DIST/support/launch.properties"
MARKER="# --- ghidra-gui-bridge (agentic testing) ---"
if ! grep -qF "$MARKER" "$PROPS"; then
  {
    echo ""
    echo "$MARKER"
    [[ -n "${JAVA_HOME:-}" ]] && echo "JAVA_HOME_OVERRIDE=${JAVA_HOME}"
    echo "VMARGS=-javaagent:${AGENT_JAR}=port=${PORT}"
  } >> "$PROPS"
  echo "==> injected -javaagent into $PROPS (port $PORT)"
else
  echo "==> javaagent already present in $PROPS"
fi

echo "==> launching Ghidra (bridge will listen on http://127.0.0.1:${PORT})"
exec "$DIST/ghidraRun"
