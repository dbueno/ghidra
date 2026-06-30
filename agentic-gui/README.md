# Building Ghidra with Nix + Agentic GUI Testing

Two things live here:

1. A **Nix build** of *this* Ghidra source tree (JDK + Gradle come entirely from
   Nix — no system Java required).
2. An **agentic GUI test harness**: a tiny in-JVM bridge that lets an automation
   agent observe and drive Ghidra's live Swing GUI over localhost HTTP.

---

## 1. Building Ghidra with Nix

Java and Gradle are provided by Nix, pinned to the nixpkgs revision whose
`ghidra` package is exactly 12.1.2 (matching `Ghidra/application.properties`).

### Dev-shell build (fast, iterative)

```sh
nix-shell --run ./build-ghidra.sh
```

- `shell.nix` — dev shell with `jdk21`, `gradle 8.14.4`, `python3` (+pip/build),
  `protobuf`. It's an *impure* shell, so the system Apple `clang` toolchain is
  still available for the native decompiler, and Gradle can fetch dependencies.
- `build-ghidra.sh` — runs `gradle -I gradle/support/fetchDependencies.gradle`
  then `gradle assembleAll`, excluding the x86_64 decompiler binaries on Apple
  silicon (they're unnecessary for an arm64 build and fail to link).
- Output: `build/dist/ghidra_12.1.2_DEV/` — a runnable distribution.

> Tip: if a build fails with a stale-environment error (e.g. *"No module named
> pip"* even though pip is present), a leftover Gradle **daemon** captured the
> old `PATH`. Run `gradle --stop` inside the shell and rebuild.

### Reproducible package/derivation

`default.nix` builds Ghidra from this checkout as a proper Nix package. It reuses
nixpkgs' from-source `ghidra` derivation — which already solves offline Gradle
dependency resolution (pinned `deps.json` + `mitmCache`) — and only swaps in this
tree as `src`:

```sh
nix-build            # -> ./result/bin/ghidra
./result/bin/ghidra  # launch
```

`flake.nix` exposes the same as `packages.default`, `devShells.default`, and
`apps.default` (`nix build` / `nix develop` / `nix run`).

---

## 2. Agentic GUI testing

macOS note: a JVM started from a non-GUI/background shell is **headless** and
cannot open windows. Only processes launched through LaunchServices (`open`) get
a desktop session. So we launch Ghidra via a generated `.app` bundle; once it's
running, its bridge is reachable over `127.0.0.1` from any shell — including an
automation agent's.

### Launch

```sh
agentic-gui/open-ghidra-gui.sh      # opens Ghidra in the desktop session
# bridge comes up on http://127.0.0.1:18217 (set GUI_BRIDGE_PORT to change)
```

Under the hood `run-ghidra-agentic.sh` injects the bridge as a `-javaagent` via
the distribution's `support/launch.properties` (`VMARGS`), so it loads only into
the Ghidra app JVM.

### Drive it

`agentic-gui/ghidra-gui` wraps the HTTP API:

```sh
ghidra-gui health                 # bridge up? AWT showing? how many windows?
ghidra-gui windows                # list top-level windows
ghidra-gui tree [WINDOW_INDEX]    # Swing component tree: class/name/text/bounds
ghidra-gui find "I Agree"        # locate components by text (and/or class)
ghidra-gui shot out.png window=4  # render a window/component to PNG

# In-JVM actions — NO macOS permissions required:
ghidra-gui invoke id=6            # Swing doClick / dispatch a click
ghidra-gui invoke text="I Agree"
ghidra-gui invoke id=9 x=40 y=12 clicks=2   # double-click a point *inside* a component
ghidra-gui invoke id=6 async=true           # don't block if the click opens a modal dialog
ghidra-gui settext id=7 "main"   # set a text field
ghidra-gui focus id=7

# Drive Ghidra's own UI — NO macOS permissions required:
ghidra-gui menu "File>Configure..."          # walk the in-frame menu bar and fire an item
ghidra-gui gaction "Load SARIF file"         # invoke a Ghidra DockingAction by name
ghidra-gui raise                             # bring the main window to the front

# Robot actions — realistic OS input; needs Accessibility/Screen Recording:
ghidra-gui click id=6
ghidra-gui typetext "main"
ghidra-gui press "ctrl shift E"
```

### Why two action layers?

- **In-JVM** (`/tree`, `/find`, `/invoke`, `/settext`, `/focus`, and `/shot`
  rendered via `Component.printAll`) dispatches events *inside* the JVM and
  renders components directly. It needs **no** macOS Accessibility or Screen
  Recording permission, so it works reliably in headless-ish CI-like contexts.
- **Robot** (`/click`, `/type`, `/key`, `/screenshot?robot=true`) generates real
  OS-level input and captures the actual screen — most faithful to a human, but
  subject to macOS TCC permissions.

Prefer the in-JVM layer for deterministic automation; reach for Robot when you
specifically need real input or a true screen capture.

### Driving Ghidra's docking framework (beyond plain Swing)

Clicking raw Swing components is enough for dialogs and license screens, but it
falls down on Ghidra's own UI. Three problems came up driving the taint/SARIF
workflow end-to-end, each of which needed a dedicated capability:

- **Menus don't open under `doClick`.** Ghidra runs an *in-frame* menu bar
  (`-Dapple.laf.useScreenMenuBar=false`). `JMenu.doClick()` won't realize the
  submenu items. **`/menu`** walks the `JMenuBar` with `JMenu.getMenuComponents()`,
  matches each `>`-separated segment by text (exact → prefix → contains), descends
  submenus without ever showing a popup, and fires the final item.

- **Local actions need a *focused* provider.** Ghidra resolves a toolbar/menu
  action's `ActionContext` from `getActiveComponentProvider()`, which depends on
  real OS window focus. A background-driven JVM has none, so clicking the
  "Load SARIF file" or "Apply all" buttons silently no-ops. **`/ghidraaction`**
  invokes a `DockingAction` *by name* via reflection (`Class.forName` against the
  Ghidra classloader), building a valid context from each `ComponentProvider`
  itself — `provider.getActionContext(null)` — and only firing on a provider where
  `isValidContext` / `isEnabledForContext` pass. This bypasses focus entirely.
  (`/raise` exists for the cases where you genuinely do want the window fronted.)

- **A click that opens a modal dialog deadlocks a single-threaded server.** The
  modal event loop blocks the EDT, so an `invokeAndWait` from the HTTP handler
  never returns. The bridge now uses a **cached thread pool** executor, and
  `/invoke` takes an **`async`** flag (dispatch via `invokeLater`, return
  immediately) so opening a dialog doesn't wedge the bridge.

Two smaller additions support the above: `/invoke` accepts component-local
**`x`/`y`** plus a **`clicks`** count (double-clicking a tree node or ticking a
table checkbox without OS-level Robot input), and `/find` / `/tree` now expose
each component's **tooltip** — Ghidra's toolbar buttons are icon-only with no text
or accessible name, so the tooltip is often the only way to identify them.

### Example: a scripted smoke test

```sh
export GUI_BRIDGE_PORT=18217
agentic-gui/ghidra-gui invoke text="I Agree"     # accept the license
agentic-gui/ghidra-gui invoke text="Close"       # dismiss Tip of the Day
agentic-gui/ghidra-gui windows | jq '.[] | select(.title|startswith("Ghidra"))'
agentic-gui/ghidra-gui shot ghidra_main.png window=4
```

### HTTP endpoints (for building your own driver / MCP tool)

| Method | Path | Body / query | Returns |
|---|---|---|---|
| GET  | `/health` | | `{ok, headless, totalWindows, showingWindows}` |
| GET  | `/windows` | | array of top-level windows |
| GET  | `/tree` | `?window=N&visibleOnly=true` | nested component tree |
| GET  | `/find` | `?text=...&class=...` | matching components (incl. `tooltip`) |
| GET  | `/screenshot` | `?window=N` / `?id=N` / `?robot=true` | `image/png` |
| POST | `/invoke` | `{id}`/`{text}`, `x,y`, `clicks`, `async` | doClick / dispatch click (optionally at a local point, multi-click, non-blocking) |
| POST | `/menu` | `{path:"File>Configure..."}` | walk the in-frame menu bar and fire an item |
| POST | `/ghidraaction` | `{name, owner?}` | invoke a Ghidra `DockingAction` by name (focus-independent, via reflection) |
| POST | `/raise` | | bring the main window to the front |
| POST | `/settext` | `{id, text}` | set text-field contents |
| POST | `/focus` | `{id}` | request focus |
| POST | `/click` | `{id}`/`{text}`/`{x,y}`, `clicks` | Robot click |
| POST | `/type` | `{text}` | Robot type string |
| POST | `/key` | `{keys:"ctrl shift E"}` | Robot key combo |

Components are addressed by stable integer `id`s assigned during tree/find walks.
`/tree` and `/find` also report each component's `tooltip`, which is often the
only label on Ghidra's icon-only toolbar buttons.

### Building just the agent

```sh
nix-shell --run agentic-gui/build-agent.sh
# -> agentic-gui/build/ghidra-gui-bridge.jar
```

The agent is pure JDK (no third-party deps), so it compiles with a plain `javac`
and loads cleanly under Ghidra's custom class loader.
