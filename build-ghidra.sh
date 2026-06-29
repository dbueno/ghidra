#!/usr/bin/env bash
# Build Ghidra from this source tree using the Nix-provided JDK21 + Gradle.
# Run inside the dev shell:   nix-shell --run ./build-ghidra.sh
set -euo pipefail
cd "$(dirname "$0")"

echo "==> Java:   $(java -version 2>&1 | head -1)"
echo "==> Gradle: $(gradle --version | awk '/^Gradle/{print $2}')"

# Arm64 macOS: Ghidra's gradle config tries to build the x86_64 decompiler
# executables too, which fail to link against the arm64 libc++. They are
# unnecessary for an arm64 distribution, so exclude them (mirrors nixpkgs).
EXCLUDES=()
if [[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]]; then
  EXCLUDES+=(-x Decompiler:linkSleighMac_x86_64Executable
            -x Decompiler:linkDecompileMac_x86_64Executable)
fi

echo "==> Step 1/2: fetch non-Maven-Central dependencies"
gradle -I gradle/support/fetchDependencies.gradle

echo "==> Step 2/2: assembleAll (uncompressed dist in build/dist)"
gradle assembleAll "${EXCLUDES[@]}"

echo "==> Build complete. Distribution:"
ls -d build/dist/*/ 2>/dev/null || ls build/dist
