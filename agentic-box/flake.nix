{
  description = "Toolchain for the agentic Ghidra/CTADL container (ghidra-box)";

  # Same nixpkgs revision the rest of this tree pins (see ../flake.nix,
  # ../shell.nix, ../default.nix): the one whose `ghidra` is exactly 12.1.2.
  # Keeping the pin identical means the JDK and Gradle inside the container are
  # bit-for-bit the ones a `nix-shell` on the host would give you.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/534ee3d8beb1737b5342995f8837e2b2705ce0d8";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "aarch64-linux"
        "x86_64-linux"
      ];
      forAll = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAll (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          jdk = pkgs.jdk21;

          # Ghidra's :createGhidraStubsWheel and buildPyPackage tasks shell out
          # to pip to build wheels, so pip/build/wheel must be importable.
          python = pkgs.python3.withPackages (
            ps: with ps; [
              pip
              setuptools
              wheel
              build
            ]
          );

          toolchain = pkgs.buildEnv {
            name = "ghidra-box-toolchain";
            # cc-wrapper and binutils-wrapper ship overlapping shims (`strings`,
            # `ar`, ...); either copy works.
            ignoreCollisions = true;
            # `man` and `info` pages roughly double the closure for no benefit
            # in a container nobody reads docs in.
            extraOutputsToInstall = [ ];

            paths = with pkgs; [
              # ---- shell + basic userland -------------------------------------
              bashInteractive
              coreutils-full
              findutils
              gnugrep
              gnused
              gawk
              gnutar
              gzip
              xz
              bzip2
              zstd
              unzip
              zip
              which
              procps
              psmisc
              util-linux
              less
              file
              diffutils
              patch
              tree
              cacert
              iproute2

              # ---- source control / fetching / agent ergonomics ---------------
              git
              curl
              wget
              openssh
              jq
              ripgrep
              fd

              # ---- Java: what actually builds Ghidra --------------------------
              jdk
              (gradle.override { java = jdk; })

              # ---- Python: Ghidra's wheel-building tasks ----------------------
              python

              # ---- native toolchain: the Decompiler, sleigh, and Rust's linker -
              gcc
              binutils
              gnumake
              cmake
              pkg-config
              bison
              flex

              # protoc for the Debugger trace-rmi/isf modules. The 31.x series
              # matches gradle.properties' ghidra.protobuf.java.version = 4.31.0;
              # newer protoc emits code the 4.31.0 runtime cannot compile. The
              # protobuf-gradle-plugin would otherwise download a glibc-FHS
              # protoc binary that will not run in a Nix container -- see
              # bin/ghidra-build, which points the plugin here via $PROTOC.
              protobuf_31

              # ---- Rust: ctadl-rs ---------------------------------------------
              cargo
              rustc
              rustfmt
              clippy
              # bzip2-sys / zstd-sys / liblzma-sys (via the `zip` crate) look for
              # a system library through pkg-config before falling back to their
              # vendored C sources.
              zlib
              openssl
              # ctadl renders call/flow graphs with dot.
              graphviz

              # ---- the X11 display the agent drives ---------------------------
              xorg.xorgserver # Xvfb
              xorg.xauth
              xorg.xdpyinfo
              xorg.xhost
              xorg.xrandr
              xorg.xset
              xorg.xkbcomp
              xkeyboard_config
              xorg.xmodmap
              xorg.xwininfo
              xorg.xwd
              xorg.xkill
              xorg.xmessage
              fluxbox # a window manager, so dialogs get decorations and focus

              # ---- observing and driving that display -------------------------
              xdotool # synthetic mouse/keyboard at the X protocol level
              wmctrl # window list / activate / move / resize
              xclip
              xsel
              imagemagick # `import -window root` -> PNG
              scrot
              ffmpeg-headless # optional screen recording of a GUI session

              # ---- remote viewing ---------------------------------------------
              x11vnc
              novnc
              python3Packages.websockify

              # ---- fonts, or every Swing label renders as boxes ----------------
              fontconfig
              dejavu_fonts
              liberation_ttf
              noto-fonts
            ];
          };
        in
        {
          inherit toolchain;
          default = toolchain;
        }
      );
    };
}
