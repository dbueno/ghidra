# ghidra-box — a container an agent can develop Ghidra plugins in

A Podman container that builds and *runs* Ghidra and `ctadl-rs`, on an X display
the agent owns outright. It can screenshot the real screen and generate real
mouse and keyboard input with no permission prompt from anybody, because there
is no macOS TCC inside a Linux container.

That is the whole reason this exists. `../agentic-gui/` already drives Ghidra's
Swing tree from inside the JVM, which is deterministic and needs no permissions
— but it cannot see a native popup menu, a drag in progress, or a tooltip, and
on macOS its Robot endpoints are gated behind Accessibility and Screen Recording
prompts a background agent can never answer. Here both layers work.

```
┌─ macOS host ──────────────────────────────────────────────────────┐
│  ./ghidra-box <cmd>                                               │
│      │                                                            │
│  ┌───▼─ podman machine "ghidra-box" (aarch64 Linux VM) ─────────┐  │
│  │  ┌── container "ghidra-box" ───────────────────────────────┐ │  │
│  │  │  Xvfb :99 ── fluxbox ── x11vnc ── websockify/noVNC      │ │  │
│  │  │       ▲                                                 │ │  │
│  │  │       │  gui shot / gui click        (X11, OS-level)    │ │  │
│  │  │  ┌────┴──── Ghidra JVM ────┐                            │ │  │
│  │  │  │  ghidra-gui-bridge.jar  │◄── ghidra-gui  (in-JVM)    │ │  │
│  │  │  └─────────────────────────┘                            │ │  │
│  │  │  toolchain: jdk21, gradle, rust, protoc, …  (all Nix)   │ │  │
│  │  └─────────────────────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────┘ │
│  bind mounts: this tree → /work/ghidra, ctadl-rs → /work/ctadl-rs  │
│  ports (127.0.0.1 only): 6080 noVNC · 5901 VNC · 18217 bridge      │
└───────────────────────────────────────────────────────────────────┘
```

---

## Quick start

```sh
# One time: podman itself, and a VM with your source tree visible to it.
nix profile install nixpkgs#podman nixpkgs#vfkit nixpkgs#gvproxy
podman machine init ghidra-box --cpus 10 --memory 24576 --disk-size 160 \
    --volume /Users/you/proj:/Users/you/proj --now

agentic-box/ghidra-box build       # build the image (slow the first time)
agentic-box/ghidra-box up          # start it; X comes up on :99
agentic-box/ghidra-box smoke       # prove capture and input actually work
agentic-box/ghidra-box ghidra-build   # build Ghidra from this tree (~8 min)
agentic-box/ghidra-box ghidra start   # launch it on the container's display
agentic-box/ghidra-box shot first     # -> agentic-box/state/shots/first.png
```

`smoke` is the check to run whenever something feels wrong. It walks the four
things this container exists to provide and stops at the first one that fails:

```
1. display          ok    X is up on :99 at 1920x1080
                    ok    window manager running
2. capture          ok    captured 36K -> …/state/shots/smoke.png
3. synthetic input  ok    test window mapped
                    ok    click reached the window and dismissed it
4. jvm              ok    Ghidra's bridge reports headless=false
```

That last line is the one that does not hold on macOS, and the reason all of
this exists.

`ghidra-box status` reports the machine, the container, the display geometry,
the window count and the bridge's health in one line each.

To watch — or take over — the same session the agent is driving:

```sh
agentic-box/ghidra-box vnc         # prints both URLs
open "http://127.0.0.1:6080/vnc.html?autoconnect=1&resize=scale"
```

---

## Driving the GUI

Two layers, and you want both.

**OS-level (`gui`, inside the container).** Real X input, real framebuffer
capture. Sees popups, drag feedback, tooltips, native menus — everything the
in-JVM layer is blind to. Coordinates are screen pixels, origin top-left.

```sh
ghidra-box shot [NAME]              # -> agentic-box/state/shots/NAME.png
ghidra-box gui shot-window 'CodeBrowser' cb   # one window, by title regex
ghidra-box gui windows              # window list with geometry (wmctrl -lG)
ghidra-box click 640 480
ghidra-box gui dblclick 640 480
ghidra-box gui rightclick 640 480
ghidra-box gui drag 100 200 400 200
ghidra-box gui scroll down 5
ghidra-box type "main"
ghidra-box gui key ctrl+shift+e Return
ghidra-box gui wait-window 'Import' 30
ghidra-box gui record demo.mp4 20   # ffmpeg x11grab
```

**In-JVM (`ghidra-gui`, the bridge from `../agentic-gui/`).** Addresses
components by id, text or tooltip instead of by pixel, so it never races the
window manager and never breaks when a panel moves. Full API in
[`../agentic-gui/README.md`](../agentic-gui/README.md).

```sh
ghidra-box bridge health
ghidra-box bridge find "I Agree"
ghidra-box bridge invoke text="I Agree"
ghidra-box bridge menu "File>Configure..."
ghidra-box bridge gaction "Load SARIF file"
ghidra-box bridge tree 4
```

The bridge is also published on the host at `127.0.0.1:18217`, so `curl` works
from a macOS shell without going through `podman exec`.

The practical rule: **find with the bridge, act with whichever fits.** Ask
`/find` or `/tree` for a component's bounds, then either `/invoke` it in-JVM or
click its center with `gui click` when you specifically want the real event
path. Screenshot after every step — that is the only thing that tells you the
UI actually went where you thought.

### The loop, start to finish

Editing a plugin and seeing the result is four commands. The edit happens in the
working tree on the host; everything after it happens in the container.

```sh
$EDITOR Ghidra/Features/Decompiler/src/main/java/.../taint/ctadl/…java
ghidra-box ghidra-build :DecompilerDependent:assemble   # or the whole assembleAll
ghidra-box ghidra restart
ghidra-box gui wait-window 'NO ACTIVE PROJECT' 120 && ghidra-box shot after
```

Then read `agentic-box/state/shots/after.png` and keep going. Getting past the
first two screens each launch is two calls:

```sh
ghidra-box bridge invoke text="I Agree"   # license
ghidra-box bridge invoke text="Close"     # Tip of the Day
```

---

## Building

```sh
ghidra-box ghidra-build            # fetchDependencies (once) + assembleAll
ghidra-box ghidra-build --deps     # re-run the dependency fetch
ghidra-box ghidra-build --clean
ghidra-box ghidra-build sleighCompile   # or any Gradle task

ghidra-box ctadl-build             # cargo build --workspace
ghidra-box ctadl-build test
ghidra-box ctadl-build clippy
```

The CTADL plugin lives in-tree under `Ghidra/Features/Decompiler`, so
`assembleAll` covers it and its unit tests run through the same passthrough:

```sh
ghidra-box ghidra-build :DecompilerDependent:test
```

`ctadl-build` links whatever binaries it produced into `/root/.local/bin`, which
is on the container's `PATH` — so the plugin's `NativeCtadlCommand` finds
`ctadl` without further arrangement.

Two things `ghidra-build` handles that a bare `gradle assembleAll` does not:

- **protoc.** `gradle/hasProtobuf.gradle` downloads a prebuilt protoc from Maven
  Central and execs it. That binary is a plain glibc/FHS ELF and will not run in
  a Nix container. An init script repoints the `generateProto` task at the
  `protobuf_31` from `flake.nix` — the same fix nixpkgs' own ghidra derivation
  applies, but as an init script, so the checkout stays pristine. The 31.x
  series is deliberate: it matches `gradle.properties`'
  `ghidra.protobuf.java.version = 4.31.0`, and a newer protoc emits code that
  runtime cannot compile.
- **Native platform.** `-PcurrentPlatformName=linux_arm_64` keeps Gradle from
  trying to cross-compile the x86_64 decompiler binaries, which gcc here cannot
  do. (`build-ghidra.sh` excludes the equivalent mac tasks on the host.)

For the *full* ctadl environment — souffle, checksarif, parquet-tools, graphviz,
ghidra-bin — the container has Nix, so its own flake works in place:

```sh
ghidra-box exec nix develop /work/ctadl-rs
```

---

## What is mounted where

| Container path | Host path | Kind |
|---|---|---|
| `/work/ghidra` | this tree | bind, read-write |
| `/work/ctadl-rs` | resolved target of `../ctadl-rs` | bind, read-write |
| `/work/state` | `agentic-box/state` | bind — screenshots and logs land here |
| `/opt/box/bin` | `agentic-box/bin` | bind, read-only — edit a helper, no rebuild |
| `/work/ghidra/build` | — | named volume |
| `/work/ghidra/.gradle` | — | named volume |
| `/work/ghidra/dependencies` | — | named volume |
| `/work/ctadl-rs/target` | — | named volume |
| `/root` | — | named volume (`~/.gradle`, `~/.cargo`, Ghidra's config) |

Source is a plain bind mount because agentic edits have to reach the working
tree — that is the point. The volumes shadow every directory where a Linux
build would otherwise overwrite the macOS build sitting at the same path: the
distribution, Gradle's state, the fetched dependencies, Cargo's target dir.

**One honest caveat.** Ghidra gives every one of its ~250 subprojects its own
`build/` directory, and a good deal of `gradle/*.gradle` addresses those with
paths relative to the *project* directory (`file("build/data/sleighArgs.txt")`),
not through `buildDir`. Redirecting them wholesale breaks the build, so the
subproject `build/` dirs stay shared with the host. In practice that costs you
recompiles, not correctness: the Java output is portable bytecode, and native
output is already namespaced per platform under `build/os/<platform>/`. If you
alternate between a host build and a container build, expect each to redo work
the other invalidated.

`agentic-box/state/` is gitignored; everything in it is disposable.

---

## Reproducibility, and where it stops

- The base image is pinned **by digest** (`nixos/nix@sha256:377d…`).
- Every tool in the container comes from `flake.nix`, pinned to the same nixpkgs
  revision as `../flake.nix`, `../shell.nix` and `../default.nix` — the one
  whose `ghidra` is exactly 12.1.2. The JDK and Gradle inside the container are
  therefore the same derivations a `nix-shell` on the host would give you.
- What is **not** reproducible: Gradle's and Cargo's own dependency resolution,
  which reaches the network at build time exactly as it does on the host. The
  container makes the *toolchain* reproducible, not those.
- One deliberate impurity: the image symlinks a glibc dynamic loader to
  `/lib/ld-linux-*.so.*`. Gradle and Cargo occasionally download prebuilt ELF
  helpers, and without a loader at its FHS address they fail with a bare "No
  such file or directory" that looks nothing like the missing-loader problem it
  is.

---

## Lifecycle and troubleshooting

```sh
ghidra-box down                 # stop; container and all caches survive
ghidra-box restart
ghidra-box destroy              # remove the container, keep the caches
ghidra-box destroy --volumes    # and drop the caches
ghidra-box logs                 # tail Xvfb / fluxbox / x11vnc / novnc logs
ghidra-box ghidra log           # tail Ghidra's own launch log
ghidra-box sh                   # interactive shell, toolchain on PATH
```

`/nix` is **not** a volume, on purpose: it ships in the image, and a stale
volume shadowing it after a rebuild would break the container outright. Anything
`nix develop` downloads lives in the container's writable layer, so it survives
`down` and `restart` but not `destroy`.

Ports are published on `127.0.0.1` only, and VNC lands on host port **5901**
because macOS Screen Sharing already owns 5900. The VNC server has no password
because it is not reachable from off the machine; if you ever republish it on
`0.0.0.0`, add one first. `BOX_VNC_PORT`, `BOX_NOVNC_PORT` and `GUI_BRIDGE_PORT`
override the host-side ports.

Common failures:

| Symptom | Cause |
|---|---|
| `podman machine 'ghidra-box' does not exist` | Run the `podman machine init` line from Quick start. |
| Screenshot is a blank grey field | Nothing is on screen yet — `ghidra-box ghidra start`, then `ghidra-box gui wait-window Ghidra`. |
| Every label renders as boxes | Fontconfig cache did not build. `ghidra-box exec fc-cache -f -v`. |
| `bridge: not answering` | Ghidra is still starting, or crashed: `ghidra-box ghidra log`. |
| Clicks land nowhere | The window is not focused. `ghidra-box gui activate '<title>'` first, or use the in-JVM `/invoke`, which does not need focus at all. |
| `address already in use` on `up` | Something on the host holds 5901, 6080 or 18217. Override with `BOX_VNC_PORT` / `BOX_NOVNC_PORT` / `GUI_BRIDGE_PORT`. |
| A helper script edit does nothing | `bin/` is mounted read-only into a *running* container. Edits take effect immediately; only `Containerfile` and `flake.nix` changes need `ghidra-box build`. |
