# The Ghidra GUI bridge

A tiny in-JVM javaagent that lets an automation agent observe and drive Ghidra's
live Swing GUI over localhost HTTP.

**It runs in the container.** Everything about launching Ghidra, capturing the
screen and generating input lives in [`../agentic-box/`](../agentic-box/README.md);
this directory is just the bridge itself and its CLI wrapper. Start there:

```sh
agentic-box/ghidra-box build
agentic-box/ghidra-box up
agentic-box/ghidra-box ghidra-build
agentic-box/ghidra-box ghidra start     # builds this agent, injects it, launches
```

The container is the whole GUI story on this branch. It replaced a macOS-native
arrangement — a generated `.app` bundle, because a JVM started from a background
shell on macOS is headless and cannot open a window — that could never make the
Robot layer work, since real input and real screen capture are gated behind
Accessibility and Screen Recording prompts a background agent cannot answer.
Inside a Linux container there is an X server the agent owns outright, and both
problems simply do not exist.

---

## Driving it

`agentic-gui/ghidra-gui` wraps the HTTP API. Inside the container it is on
`PATH`; from the host, `ghidra-box bridge <subcommand>` is the same thing.

```sh
ghidra-box bridge health                 # bridge up? AWT showing? how many windows?
ghidra-box bridge windows                # list top-level windows
ghidra-box bridge tree [WINDOW_INDEX]    # Swing component tree: class/name/text/bounds
ghidra-box bridge find "I Agree"         # locate components by text (and/or class)
ghidra-box bridge shot out.png window=4  # render a window/component to PNG

# In-JVM actions:
ghidra-box bridge invoke id=6            # Swing doClick / dispatch a click
ghidra-box bridge invoke text="I Agree"
ghidra-box bridge invoke id=9 x=40 y=12 clicks=2   # double-click a point *inside* a component
ghidra-box bridge invoke id=6 async=true           # don't block if the click opens a modal dialog
ghidra-box bridge settext id=7 "main"    # set a text field
ghidra-box bridge focus id=7

# Drive Ghidra's own UI:
ghidra-box bridge menu "File>Configure..."   # walk the in-frame menu bar and fire an item
ghidra-box bridge gaction "Load SARIF file"  # invoke a Ghidra DockingAction by name
ghidra-box bridge raise                      # bring the main window to the front

# Robot actions — real OS-level input, and in the container they need no
# permission from anyone:
ghidra-box bridge click id=6
ghidra-box bridge typetext "main"
ghidra-box bridge press "ctrl shift E"
```

The bridge is also published on the host at `127.0.0.1:18217`, so plain `curl`
works from any macOS shell.

## Two action layers, and when to reach for each

- **In-JVM** (`/tree`, `/find`, `/invoke`, `/settext`, `/focus`, and `/shot`
  rendered via `Component.printAll`) dispatches events *inside* the JVM and
  renders components directly. It addresses things by id, text or tooltip
  instead of by pixel, so it never races the window manager and never breaks
  when a panel moves. Prefer it for deterministic automation.
- **Robot** (`/click`, `/type`, `/key`, `/screenshot?robot=true`) generates real
  OS-level input and captures the actual screen. Reach for it when you
  specifically need the real event path.

Alongside both there is `gui` — the container's X11 layer (`ghidra-box shot`,
`ghidra-box click`, `ghidra-box gui …`). It sees things no JVM-side layer can:
native popup menus, drag feedback, tooltips, and anything drawn by another
process. The practical rule is **find with the bridge, act with whichever fits**,
and screenshot after every step — that is the only thing that tells you the UI
actually went where you thought.

## Driving Ghidra's docking framework (beyond plain Swing)

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
  never returns. The bridge uses a **cached thread pool** executor, and
  `/invoke` takes an **`async`** flag (dispatch via `invokeLater`, return
  immediately) so opening a dialog doesn't wedge the bridge.

Two smaller additions support the above: `/invoke` accepts component-local
**`x`/`y`** plus a **`clicks`** count (double-clicking a tree node or ticking a
table checkbox without OS-level Robot input), and `/find` / `/tree` expose
each component's **tooltip** — Ghidra's toolbar buttons are icon-only with no text
or accessible name, so the tooltip is often the only way to identify them.

## Example: a scripted smoke test

```sh
ghidra-box ghidra start
ghidra-box bridge invoke text="I Agree"     # accept the license
ghidra-box bridge invoke text="Close"       # dismiss Tip of the Day
ghidra-box gui wait-window 'NO ACTIVE PROJECT' 120
ghidra-box shot ghidra_main                 # -> agentic-box/state/shots/ghidra_main.png
```

## HTTP endpoints (for building your own driver / MCP tool)

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

The agent binds `127.0.0.1` on purpose. The container's entrypoint runs a small
forwarder (`agentic-box/bin/box-portfwd`) so the published host port reaches it
without the bridge itself having to listen on a routable address.

## Building just the agent

`ghidra-box ghidra start` builds it automatically when it is missing. To do it
by hand:

```sh
ghidra-box exec /work/ghidra/agentic-gui/build-agent.sh
# -> agentic-gui/build/ghidra-gui-bridge.jar
```

The agent is pure JDK (no third-party deps), so it compiles with a plain `javac`
and loads cleanly under Ghidra's custom class loader.

---

## Building Ghidra itself

In the container, which is where this branch expects you to build:

```sh
ghidra-box ghidra-build            # fetchDependencies + assembleAll
ghidra-box ghidra-build :DecompilerDependent:test
```

The host-side Nix build still works if you want it — `nix-shell --run
./build-ghidra.sh` for an iterative build into `build/dist/`, or `nix-build` for
a proper derivation via `default.nix`. Both are pinned to the nixpkgs revision
whose `ghidra` is exactly 12.1.2, matching `Ghidra/application.properties`. The
container's toolchain shares that pin, so the JDK and Gradle are the same
derivations either way.
