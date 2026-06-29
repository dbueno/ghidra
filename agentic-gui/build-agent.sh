#!/usr/bin/env bash
# Compile the GUI bridge javaagent into agentic-gui/build/ghidra-gui-bridge.jar.
# Run inside the dev shell:  nix-shell --run agentic-gui/build-agent.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="$here/build"
mkdir -p "$out/classes"

echo "==> javac ($(java -version 2>&1 | head -1))"
javac -d "$out/classes" "$here/src/guibridge/GuiAgent.java"

echo "==> jar"
jar --create --file "$out/ghidra-gui-bridge.jar" \
    --manifest "$here/manifest.mf" \
    -C "$out/classes" .

echo "==> built $out/ghidra-gui-bridge.jar"
