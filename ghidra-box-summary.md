# ghidra-box — what was built, and what it does

A Podman container that builds and runs Ghidra and `ctadl-rs`, on an X display an
agent owns outright. It screenshots the real screen and generates real mouse and
keyboard input with no permission prompt, because there is no macOS TCC inside a
Linux container.

Everything below was built and verified end to end on this machine.

## The problem it removes

The existing `agentic-gui/` bridge drives Ghidra's Swing tree from inside the
JVM. That works and needs no permissions, but it cannot see a native popup menu,
a drag in progress, or a tooltip. Its Robot layer — real input, real screen
capture — could cover those, except on macOS it is gated behind Accessibility and
Screen Recording prompts a background agent cannot answer. And a JVM started from
a background shell on macOS is headless outright, which is why there was a
generated `.app` bundle just to get a window on screen.

In the container the JVM reports `headless=false` and the Robot endpoints work
unprompted. Both layers are live at once.

## What is in `agentic-box/`

| File | What it is |
|---|---|
| `ghidra-box` | The host-side CLI. Everything goes through it. |
| `Containerfile` | Image, `FROM nixos/nix` pinned by digest. |
| `flake.nix` / `flake.lock` | The whole toolchain, pinned to the same nixpkgs rev as `../flake.nix`. |
| `bin/box-entrypoint` | Brings up Xvfb, fluxbox, x11vnc, noVNC, the port forwarder. |
| `bin/gui` | The X11 layer: capture, click, type, key, drag, scroll, record. |
| `bin/ghidra-build` | Gradle with the two fixes the container needs. |
| `bin/ghidra-run` | Launch/stop Ghidra with the bridge attached. |
| `bin/ctadl-build` | Cargo, plus linking the binaries onto `PATH`. |
| `bin/box-smoke` | Proves display, capture, input and JVM in one command. |
| `bin/box-portfwd` | Makes the loopback-bound bridge reachable from the host. |

## Verified

```
ghidra-box build            image built; 932 fonts registered, JDK 21 resolved
ghidra-box up               X on :99 at 1920x1080, WM running
ghidra-box smoke            all four checks pass
ghidra-box ghidra-build     BUILD SUCCESSFUL in 7m50s, 634 tasks
                            incl. native decompiler + sleigh for linux_arm_64
ghidra-box ctadl-build      Finished dev profile in 2m19s; ctadl 0.1.2 on PATH
ghidra-box ghidra start     bridge answers {"ok":true,"headless":false}
```

The GUI loop was driven all the way through: a real X11 click at (893, 767)
dismissed the license dialog; the in-JVM bridge closed Tip of the Day; a click
focused the project filter field and `gui type` entered text into it, confirmed
by a window-scoped screenshot. The Robot screenshot endpoint — the one TCC blocks
on macOS — returned a 31KB PNG with no prompt.

## Two bugs found and fixed while testing

**`ghidra-run stop` never stopped anything.** It tracked the pid of `ghidraRun`,
a shell script that hands off to java and exits, so the recorded pid was dead
within a second and `running()` always said no. `restart` therefore left two
Ghidras alive, and the second silently lost the bridge port to the first — the
health check answered from the stale JVM. Now it tracks the JVM by pattern,
escalates SIGTERM to SIGKILL, and verifies the process is actually gone.

**The published bridge port reached nothing.** `GuiAgent` binds `127.0.0.1`, and
a published container port maps to eth0, not loopback — so `curl` from the host
got an empty reply while the in-container check passed. `bin/box-portfwd`, a
small Python hop from `0.0.0.0:18227` to `127.0.0.1:18217`, fixes it without
loosening the bridge's own bind address. `ghidra-box status` now asks from inside
the container and reports host reachability as a separate line, so the two can
never be confused again.

## Decisions worth knowing

**Source is a plain bind mount; build outputs are named volumes.** Agentic edits
have to reach the working tree — that is the point. But the top-level `build/`,
`.gradle/`, `dependencies/`, Cargo's `target/` and `/root` are container-private
volumes, so a Linux build never overwrites the macOS build at the same path.
Verified: after the container build, the host's `build/dist/ghidra_12.1.2_DEV`,
`ctadl-rs/target/` and `dependencies/` were all still intact.

**One honest gap.** Ghidra gives each of ~250 subprojects its own `build/` dir,
and much of `gradle/*.gradle` addresses those with paths relative to the *project*
directory (`file("build/data/sleighArgs.txt")`), not through `buildDir`.
Redirecting them wholesale breaks the build, so subproject `build/` dirs stay
shared with the host. That costs recompiles, not correctness: Java output is
portable bytecode and native output is already namespaced under
`build/os/<platform>/`.

**protoc.** `gradle/hasProtobuf.gradle` downloads a prebuilt protoc from Maven and
execs it; that binary is a glibc/FHS ELF and will not run in a Nix container. An
init script repoints the task at `protobuf_31` from the flake — the same fix
nixpkgs' own ghidra derivation applies, but as an init script, so the checkout
stays pristine. The 31.x series matches `ghidra.protobuf.java.version = 4.31.0`.

**Reproducibility, and where it stops.** Base image pinned by digest; every tool
from `flake.nix` on the same nixpkgs rev as the rest of the tree, so the JDK and
Gradle in the container are the same derivations `nix-shell` gives you on the
host. Not reproducible: Gradle's and Cargo's own dependency resolution, which
reaches the network exactly as it does on the host. One deliberate impurity — a
glibc loader symlinked to `/lib/ld-linux-*.so.*`, because downloaded ELF helpers
otherwise fail with a bare "No such file or directory".

**`/nix` is not a volume.** It ships in the image; a stale volume shadowing it
after a rebuild would break the container outright. Whatever `nix develop`
downloads lives in the writable layer and survives `down`, not `destroy`.

## Changes outside `agentic-box/`

- `agentic-gui/README.md` rewritten around the container. The macOS `.app` /
  headless material is gone; the bridge API reference stays, since it is still
  the truth.
- Deleted `agentic-gui/open-ghidra-gui.sh` and `run-ghidra-agentic.sh` — both
  existed only to work around macOS headlessness, and nothing else referenced
  them.
- `agentic-box/.gitignore` re-includes `bin/` and `flake.lock`, which the
  repository root's `/*/bin/` and `*.lock` rules were silently swallowing.

## Set up on this machine

`podman` 5.8.4, `vfkit` and `gvproxy` installed via `nix profile`. A machine
named `ghidra-box` (10 CPUs, 24 GB, 160 GB) with `/Users/dbueno/proj` mounted
through. VNC lands on host port **5901** because macOS Screen Sharing owns 5900.
Ports are published on `127.0.0.1` only.

`~/.nix-profile/bin` is not on your login `PATH` yet, so `podman` will not be
found in a fresh shell until you add it — `ghidra-box` prepends it itself, so the
CLI works regardless.

## Where to start

`agentic-box/README.md` has the quick start, the full command surface, the mount
table and a troubleshooting table. The loop, in short:

```sh
$EDITOR Ghidra/Features/Decompiler/src/main/java/.../taint/ctadl/…java
agentic-box/ghidra-box ghidra-build :DecompilerDependent:assemble
agentic-box/ghidra-box ghidra restart
agentic-box/ghidra-box gui wait-window 'NO ACTIVE PROJECT' 120
agentic-box/ghidra-box shot after     # then read agentic-box/state/shots/after.png
```
