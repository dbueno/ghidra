# Reproducible Nix dev shell for building Ghidra from this source tree.
#
# Pinned to the same nixpkgs revision that packages ghidra 12.1.2 (matching
# this checkout's application.version), so the JDK/Gradle versions line up with
# what upstream nixpkgs uses to build Ghidra.
#
# Usage:
#   nix-shell                      # drop into a shell with jdk21 + gradle
#   nix-shell --run './build-ghidra.sh'
#
# Notes:
# * This is an *impure* shell (regular nix-shell), so the system Apple clang
#   toolchain at /usr/bin remains on PATH for building the native decompiler,
#   and Gradle can reach the network to fetch dependencies.
# * Java/Gradle themselves come entirely from Nix (no system JDK required).
{
  pkgs ? import (fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/534ee3d8beb1737b5342995f8837e2b2705ce0d8.tar.gz";
    sha256 = "sha256-FyWKrhnTe6Ytw/zzYTB52Wboe5a7UqikUG+lV5puCMY=";
  }) { },
}:

let
  jdk = pkgs.jdk21;
in
pkgs.mkShell {
  name = "ghidra-dev";

  packages = [
    jdk
    (pkgs.gradle.override { java = jdk; })
    # Python with pip/build/wheel: Ghidra's :createGhidraStubsWheel and
    # buildPyPackage tasks shell out to pip to build wheels.
    (pkgs.python3.withPackages (ps: with ps; [
      pip
      setuptools
      wheel
      build
    ]))
    pkgs.protobuf # used by the Debugger trace-rmi/isf modules
    pkgs.unzip
    pkgs.curl # used by the agentic GUI test driver
    pkgs.jq

    # Rust, for building the ctadl-rs workspace that lives beside this tree.
    # This is the compile-only subset of ctadl-rs's own devShell; the extras it
    # carries (souffle, parquet-tools, graphviz, ghidra-bin, ...) are for
    # running and testing ctadl, not for `cargo build`, so they stay over there.
    # ctadl-rs pins 1.94.1 in rust-toolchain.toml, which only rustup reads --
    # this nixpkgs ships 1.95.0, which satisfies the same edition/resolver
    # requirements.
    pkgs.cargo
    pkgs.rustc
    pkgs.rustfmt
    pkgs.clippy
    # bzip2-sys / zstd-sys / liblzma-sys (pulled in by the `zip` dependency)
    # look for a system library through pkg-config before falling back to their
    # vendored C sources.
    pkgs.pkg-config
    pkgs.bzip2
  ];

  # Ghidra's launcher and Gradle both honor JAVA_HOME; point it at the Nix JDK.
  JAVA_HOME = jdk.home;

  # So rust-analyzer can find the standard library sources.
  RUST_SRC_PATH = pkgs.rustPlatform.rustLibSrc;

  shellHook = ''
    echo "ghidra-dev shell: JDK $(java -version 2>&1 | head -1)"
    echo "                  Gradle $(gradle --version 2>/dev/null | awk '/^Gradle/{print $2}')"
    echo "                  JAVA_HOME=$JAVA_HOME"
    echo "                  $(rustc --version 2>/dev/null), $(cargo --version 2>/dev/null)"
  '';
}
