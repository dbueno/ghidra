# A Nix derivation that builds Ghidra *from this source tree*.
#
#   nix-build            # -> ./result/bin/ghidra
#   nix-build -A ghidra  # same thing
#   ./result/bin/ghidra  # launch the GUI
#
# How it works: nixpkgs already packages Ghidra 12.1.2 from source
# (pkgs.ghidra, provenance "fromSource"). That derivation solves the genuinely
# hard part of a sandboxed Gradle build -- offline dependency resolution via a
# pinned deps.json + mitmCache. We reuse all of that and only swap in this
# checkout as `src`, so the bytes that get compiled are *yours*, not the
# upstream release tarball.
#
# Pinned to the nixpkgs revision whose ghidra is exactly 12.1.2, matching this
# tree's Ghidra/application.properties.
{
  pkgs ? import (fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/534ee3d8beb1737b5342995f8837e2b2705ce0d8.tar.gz";
    sha256 = "sha256-FyWKrhnTe6Ytw/zzYTB52Wboe5a7UqikUG+lV5puCMY=";
  }) { },
}:

let
  lib = pkgs.lib;

  # Git revision of this checkout, baked into the About box / version string.
  ghidraRevision = "c0f584bf229fffba61b36431f3ce30c0c3e4e682";

  # This source tree, minus build outputs and VCS metadata, so the derivation
  # input hash doesn't churn on every local rebuild.
  localSrc = lib.cleanSourceWith {
    name = "ghidra-src";
    src = ./.;
    filter =
      path: type:
      let
        base = baseNameOf path;
      in
      !(builtins.elem base [
        "build"
        "dependencies"
        ".gradle"
        "result"
        ".git"
      ]);
  };

  ghidra-local = pkgs.ghidra.overrideAttrs (old: {
    pname = "ghidra-local";
    src = localSrc;

    # Upstream applies three patches. The first two apply cleanly to this tree:
    #   0001 - use the Nix protoc instead of the bundled prebuilt one (required
    #          for the offline sandbox build of the Debugger trace-rmi modules)
    #   0002 - load extensions from the Nix output directory
    # The third (cosmetic build-datestamp removal) does not apply to this
    # release branch and is irrelevant to the dependency set, so we drop it.
    patches = lib.take 2 old.patches;

    # Reimplement upstream's postPatch without depending on the git metadata
    # files (COMMIT / SOURCE_DATE_EPOCH) that its fetchFromGitHub postFetch
    # created -- those don't exist when src is a plain path.
    postPatch = ''
      sed -i -e 's/application\.release\.name=.*/application.release.name=NIX/' \
        Ghidra/application.properties
      echo "application.build.date=2026-Jun-29"        >> Ghidra/application.properties
      echo "application.build.date.short=20260629"     >> Ghidra/application.properties
      echo "application.revision.ghidra=${ghidraRevision}" >> Ghidra/application.properties

      # Point the protobuf-gradle-plugin (enabled by patch 0001) at the Nix protoc.
      # Must match gradle.properties' ghidra.protobuf.java.version (4.31.0, i.e.
      # the protoc 31.x series) -- the default nixpkgs protobuf (34.x) emits
      # generated code that the 4.31.0 protobuf-java runtime can't compile.
      tee -a Ghidra/Debug/Debugger-{isf,rmi-trace}/build.gradle <<HERE
      protobuf {
        protoc {
          path = '${pkgs.protobuf_31}/bin/protoc'
        }
      }
      HERE
    '';
  });
in
ghidra-local // {
  inherit ghidra-local;
  ghidra = ghidra-local; # `nix-build -A ghidra`
  ghidra-upstream = pkgs.ghidra; # the unmodified nixpkgs build, for comparison
}
