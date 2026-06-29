package guibridge;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import javax.accessibility.AccessibleContext;
import javax.imageio.ImageIO;
import javax.swing.AbstractButton;
import javax.swing.JComponent;
import javax.swing.SwingUtilities;
import javax.swing.text.JTextComponent;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Frame;
import java.awt.Graphics2D;
import java.awt.GraphicsEnvironment;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.Robot;
import java.awt.Toolkit;
import java.awt.Window;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * In-JVM GUI automation bridge for Ghidra (a Java/Swing app), loaded as a
 * {@code -javaagent}. It starts a small HTTP server that lets an external agent
 * <b>observe</b> the live Swing component tree (with text + screen bounds) and
 * <b>act</b> on it.
 *
 * <p>Two interaction layers are provided:
 * <ul>
 *   <li><b>In-JVM</b> (no OS permissions needed): {@code /tree}, {@code /find},
 *       {@code /invoke} (Swing doClick), {@code /settext}, {@code /focus}, and
 *       {@code /screenshot} which renders components via {@code printAll} rather
 *       than capturing the screen -- so it works even without macOS Screen
 *       Recording permission.</li>
 *   <li><b>Robot</b> (realistic OS input; needs macOS Accessibility / Screen
 *       Recording): {@code /click}, {@code /type}, {@code /key}, and
 *       {@code /screenshot?robot=true}.</li>
 * </ul>
 *
 * No third-party dependencies -- only the JDK, so it compiles with a plain
 * {@code javac} and loads cleanly under Ghidra's custom class loader.
 */
public final class GuiAgent {

    private static final IdentityHashMap<Component, Integer> IDS = new IdentityHashMap<>();
    private static final Map<Integer, Component> BY_ID = new LinkedHashMap<>();
    private static final AtomicInteger SEQ = new AtomicInteger(1);

    private static volatile Robot robot;

    public static void premain(String agentArgs, Instrumentation inst) {
        int port = 18217;
        if (agentArgs != null) {
            for (String kv : agentArgs.split(",")) {
                String[] p = kv.split("=", 2);
                if (p.length == 2 && p[0].trim().equals("port")) {
                    try {
                        port = Integer.parseInt(p[1].trim());
                    } catch (NumberFormatException ignore) {
                    }
                }
            }
        }
        final int boundPort = port;
        Thread t = new Thread(() -> startServer(boundPort), "ghidra-gui-bridge");
        t.setDaemon(true);
        t.start();
    }

    // Also support attach-on-the-fly (jcmd / VirtualMachine.attach).
    public static void agentmain(String agentArgs, Instrumentation inst) {
        premain(agentArgs, inst);
    }

    private static void startServer(int port) {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
            server.createContext("/health", wrap(GuiAgent::health));
            server.createContext("/windows", wrap(GuiAgent::windows));
            server.createContext("/tree", wrap(GuiAgent::tree));
            server.createContext("/find", wrap(GuiAgent::find));
            server.createContext("/screenshot", GuiAgent::screenshot);
            server.createContext("/invoke", wrap(GuiAgent::invoke));
            server.createContext("/settext", wrap(GuiAgent::settext));
            server.createContext("/focus", wrap(GuiAgent::focus));
            server.createContext("/click", wrap(GuiAgent::click));
            server.createContext("/type", wrap(GuiAgent::type));
            server.createContext("/key", wrap(GuiAgent::key));
            server.setExecutor(null);
            server.start();
            System.err.println("[gui-bridge] listening on http://127.0.0.1:" + port);
        } catch (IOException e) {
            System.err.println("[gui-bridge] failed to start: " + e);
        }
    }

    // ----------------------------------------------------------------- routes

    private static String health(HttpExchange ex, Map<String, String> q) {
        boolean headless = GraphicsEnvironment.isHeadless();
        Window[] ws = headless ? new Window[0] : Window.getWindows();
        int showing = 0;
        for (Window w : ws) {
            if (w.isShowing()) {
                showing++;
            }
        }
        return "{\"ok\":true,\"headless\":" + headless
                + ",\"totalWindows\":" + ws.length
                + ",\"showingWindows\":" + showing + "}";
    }

    private static String windows(HttpExchange ex, Map<String, String> q) throws Exception {
        StringBuilder sb = new StringBuilder("[");
        onEdt(() -> {
            Window[] ws = Window.getWindows();
            boolean first = true;
            for (int i = 0; i < ws.length; i++) {
                Window w = ws[i];
                if (!first) {
                    sb.append(',');
                }
                first = false;
                String title = "";
                if (w instanceof Frame f) {
                    title = f.getTitle();
                } else if (w instanceof java.awt.Dialog d) {
                    title = d.getTitle();
                }
                Rectangle b = w.getBounds();
                sb.append("{\"index\":").append(i)
                        .append(",\"id\":").append(idOf(w))
                        .append(",\"class\":\"").append(esc(w.getClass().getName())).append('"')
                        .append(",\"title\":\"").append(esc(title)).append('"')
                        .append(",\"showing\":").append(w.isShowing())
                        .append(",\"active\":").append(w.isActive())
                        .append(",\"bounds\":").append(rect(b))
                        .append('}');
            }
        });
        return sb.append(']').toString();
    }

    private static String tree(HttpExchange ex, Map<String, String> q) throws Exception {
        boolean visibleOnly = !"false".equals(q.getOrDefault("visibleOnly", "true"));
        Integer windowIndex = q.containsKey("window") ? Integer.parseInt(q.get("window")) : null;
        StringBuilder sb = new StringBuilder();
        onEdt(() -> {
            Window[] ws = Window.getWindows();
            List<Window> roots = new ArrayList<>();
            if (windowIndex != null) {
                if (windowIndex >= 0 && windowIndex < ws.length) {
                    roots.add(ws[windowIndex]);
                }
            } else {
                // Only top-level windows are roots; owned windows (dialogs,
                // popups) are nested under their owner by writeNode, so listing
                // them here too would duplicate them.
                for (Window w : ws) {
                    if (w.getOwner() == null && (!visibleOnly || w.isShowing())) {
                        roots.add(w);
                    }
                }
            }
            sb.append('[');
            for (int i = 0; i < roots.size(); i++) {
                if (i > 0) {
                    sb.append(',');
                }
                writeNode(sb, roots.get(i), visibleOnly);
            }
            sb.append(']');
        });
        return sb.toString();
    }

    private static String find(HttpExchange ex, Map<String, String> q) throws Exception {
        String text = q.get("text");
        String cls = q.get("class");
        boolean visibleOnly = !"false".equals(q.getOrDefault("visibleOnly", "true"));
        List<String> hits = new ArrayList<>();
        onEdt(() -> {
            // Walk only top-level windows; collectMatches recurses into owned
            // windows, so iterating all of Window.getWindows() would double-count.
            for (Window w : Window.getWindows()) {
                if (w.getOwner() != null) {
                    continue;
                }
                if (visibleOnly && !w.isShowing()) {
                    continue;
                }
                collectMatches(w, text, cls, visibleOnly, hits);
            }
        });
        return "[" + String.join(",", hits) + "]";
    }

    private static String invoke(HttpExchange ex, Map<String, String> q) throws Exception {
        Map<String, String> body = parseJson(readBody(ex));
        Component c = resolve(body);
        if (c == null) {
            return err("component not found");
        }
        final boolean[] done = {false};
        onEdt(() -> {
            if (c instanceof AbstractButton b) {
                b.doClick();
                done[0] = true;
            } else {
                // Synthesize a left click in the component's center.
                int x = c.getWidth() / 2;
                int y = c.getHeight() / 2;
                long now = System.currentTimeMillis();
                c.dispatchEvent(new java.awt.event.MouseEvent(c,
                        java.awt.event.MouseEvent.MOUSE_PRESSED, now, 0, x, y, 1, false,
                        java.awt.event.MouseEvent.BUTTON1));
                c.dispatchEvent(new java.awt.event.MouseEvent(c,
                        java.awt.event.MouseEvent.MOUSE_RELEASED, now, 0, x, y, 1, false,
                        java.awt.event.MouseEvent.BUTTON1));
                c.dispatchEvent(new java.awt.event.MouseEvent(c,
                        java.awt.event.MouseEvent.MOUSE_CLICKED, now, 0, x, y, 1, false,
                        java.awt.event.MouseEvent.BUTTON1));
                done[0] = true;
            }
        });
        return "{\"ok\":" + done[0] + ",\"id\":" + idOf(c) + "}";
    }

    private static String settext(HttpExchange ex, Map<String, String> q) throws Exception {
        Map<String, String> body = parseJson(readBody(ex));
        Component c = resolve(body);
        String text = body.getOrDefault("text", "");
        if (!(c instanceof JTextComponent tc)) {
            return err("component is not a text field");
        }
        onEdt(() -> tc.setText(text));
        return "{\"ok\":true,\"id\":" + idOf(c) + "}";
    }

    private static String focus(HttpExchange ex, Map<String, String> q) throws Exception {
        Map<String, String> body = parseJson(readBody(ex));
        Component c = resolve(body);
        if (c == null) {
            return err("component not found");
        }
        onEdt(c::requestFocusInWindow);
        return "{\"ok\":true,\"id\":" + idOf(c) + "}";
    }

    private static String click(HttpExchange ex, Map<String, String> q) throws Exception {
        Map<String, String> body = parseJson(readBody(ex));
        Point p = screenPoint(body);
        if (p == null) {
            return err("need {id|text} of a showing component, or {x,y}");
        }
        int clicks = intOr(body, "clicks", 1);
        Robot r = robot();
        r.mouseMove(p.x, p.y);
        for (int i = 0; i < clicks; i++) {
            r.mousePress(InputEvent.BUTTON1_DOWN_MASK);
            r.mouseRelease(InputEvent.BUTTON1_DOWN_MASK);
        }
        return "{\"ok\":true,\"x\":" + p.x + ",\"y\":" + p.y + "}";
    }

    private static String type(HttpExchange ex, Map<String, String> q) throws Exception {
        Map<String, String> body = parseJson(readBody(ex));
        String text = body.getOrDefault("text", "");
        Robot r = robot();
        for (int i = 0; i < text.length(); i++) {
            typeChar(r, text.charAt(i));
        }
        return "{\"ok\":true,\"typed\":" + text.length() + "}";
    }

    private static String key(HttpExchange ex, Map<String, String> q) throws Exception {
        Map<String, String> body = parseJson(readBody(ex));
        String combo = body.getOrDefault("keys", "");
        String[] parts = combo.trim().split("\\s+");
        List<Integer> codes = new ArrayList<>();
        for (String part : parts) {
            codes.add(keyCode(part));
        }
        Robot r = robot();
        for (int code : codes) {
            r.keyPress(code);
        }
        for (int i = codes.size() - 1; i >= 0; i--) {
            r.keyRelease(codes.get(i));
        }
        return "{\"ok\":true,\"keys\":\"" + esc(combo) + "\"}";
    }

    /** PNG of a window/component. In-JVM render by default; ?robot=true for real screen capture. */
    private static void screenshot(HttpExchange ex) throws IOException {
        try {
            Map<String, String> q = query(ex);
            boolean useRobot = "true".equals(q.get("robot"));
            BufferedImage img;
            if (useRobot) {
                Rectangle area = robotArea(q);
                img = robot().createScreenCapture(area);
            } else {
                img = renderComponent(q);
            }
            if (img == null) {
                sendText(ex, 404, err("nothing to capture"));
                return;
            }
            byte[] png;
            try (var baos = new java.io.ByteArrayOutputStream()) {
                ImageIO.write(img, "png", baos);
                png = baos.toByteArray();
            }
            ex.getResponseHeaders().add("Content-Type", "image/png");
            ex.sendResponseHeaders(200, png.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(png);
            }
        } catch (Exception e) {
            sendText(ex, 500, err(String.valueOf(e)));
        }
    }

    // -------------------------------------------------------------- rendering

    private static BufferedImage renderComponent(Map<String, String> q) throws Exception {
        final BufferedImage[] out = {null};
        onEdt(() -> {
            Component c = targetComponent(q);
            if (c == null || c.getWidth() <= 0 || c.getHeight() <= 0) {
                return;
            }
            BufferedImage img = new BufferedImage(c.getWidth(), c.getHeight(),
                    BufferedImage.TYPE_INT_ARGB);
            Graphics2D g = img.createGraphics();
            g.setColor(Color.WHITE);
            g.fillRect(0, 0, c.getWidth(), c.getHeight());
            c.printAll(g);
            g.dispose();
            out[0] = img;
        });
        return out[0];
    }

    private static Component targetComponent(Map<String, String> q) {
        if (q.containsKey("id")) {
            return BY_ID.get(Integer.parseInt(q.get("id")));
        }
        Window[] ws = Window.getWindows();
        int idx = q.containsKey("window") ? Integer.parseInt(q.get("window")) : -1;
        if (idx >= 0 && idx < ws.length) {
            return ws[idx];
        }
        // Default: the active/focused window, else the first showing one.
        Window best = null;
        for (Window w : ws) {
            if (w.isActive()) {
                return w;
            }
            if (best == null && w.isShowing()) {
                best = w;
            }
        }
        return best;
    }

    private static Rectangle robotArea(Map<String, String> q) {
        if (q.containsKey("id") || q.containsKey("window")) {
            final Rectangle[] r = {null};
            try {
                onEdt(() -> {
                    Component c = targetComponent(q);
                    if (c != null && c.isShowing()) {
                        r[0] = new Rectangle(c.getLocationOnScreen(), c.getSize());
                    }
                });
            } catch (Exception ignore) {
            }
            if (r[0] != null) {
                return r[0];
            }
        }
        return new Rectangle(Toolkit.getDefaultToolkit().getScreenSize());
    }

    // ------------------------------------------------------------ tree walking

    private static void writeNode(StringBuilder sb, Component c, boolean visibleOnly) {
        sb.append('{');
        sb.append("\"id\":").append(idOf(c));
        sb.append(",\"class\":\"").append(esc(c.getClass().getName())).append('"');
        String name = c.getName();
        if (name != null) {
            sb.append(",\"name\":\"").append(esc(name)).append('"');
        }
        String text = textOf(c);
        if (text != null && !text.isEmpty()) {
            sb.append(",\"text\":\"").append(esc(text)).append('"');
        }
        String acc = accessibleName(c);
        if (acc != null && !acc.isEmpty() && !acc.equals(text)) {
            sb.append(",\"accessibleName\":\"").append(esc(acc)).append('"');
        }
        sb.append(",\"enabled\":").append(c.isEnabled());
        sb.append(",\"showing\":").append(c.isShowing());
        if (c.isShowing()) {
            try {
                sb.append(",\"screenBounds\":")
                        .append(rect(new Rectangle(c.getLocationOnScreen(), c.getSize())));
            } catch (Exception ignore) {
            }
        }
        if (c instanceof Container ct) {
            List<Component> kids = new ArrayList<>();
            for (Component k : ct.getComponents()) {
                if (!visibleOnly || k.isVisible()) {
                    kids.add(k);
                }
            }
            // Windows own child windows too (e.g. popups); include them as children.
            if (c instanceof Window w) {
                for (Window ow : w.getOwnedWindows()) {
                    if (ow.isShowing()) {
                        kids.add(ow);
                    }
                }
            }
            if (!kids.isEmpty()) {
                sb.append(",\"children\":[");
                for (int i = 0; i < kids.size(); i++) {
                    if (i > 0) {
                        sb.append(',');
                    }
                    writeNode(sb, kids.get(i), visibleOnly);
                }
                sb.append(']');
            }
        }
        sb.append('}');
    }

    private static void collectMatches(Component c, String text, String cls,
            boolean visibleOnly, List<String> hits) {
        if (!visibleOnly || c.isShowing()) {
            boolean ok = true;
            if (text != null) {
                String t = textOf(c);
                String a = accessibleName(c);
                ok = (t != null && t.toLowerCase().contains(text.toLowerCase()))
                        || (a != null && a.toLowerCase().contains(text.toLowerCase()));
            }
            if (ok && cls != null) {
                ok = c.getClass().getName().toLowerCase().contains(cls.toLowerCase());
            }
            if (ok && (text != null || cls != null)) {
                StringBuilder sb = new StringBuilder("{");
                sb.append("\"id\":").append(idOf(c));
                sb.append(",\"class\":\"").append(esc(c.getClass().getName())).append('"');
                String t = textOf(c);
                if (t != null) {
                    sb.append(",\"text\":\"").append(esc(t)).append('"');
                }
                sb.append(",\"enabled\":").append(c.isEnabled());
                sb.append(",\"showing\":").append(c.isShowing());
                if (c.isShowing()) {
                    try {
                        sb.append(",\"screenBounds\":")
                                .append(rect(new Rectangle(c.getLocationOnScreen(), c.getSize())));
                    } catch (Exception ignore) {
                    }
                }
                hits.add(sb.append('}').toString());
            }
        }
        if (c instanceof Container ct) {
            for (Component k : ct.getComponents()) {
                collectMatches(k, text, cls, visibleOnly, hits);
            }
            if (c instanceof Window w) {
                for (Window ow : w.getOwnedWindows()) {
                    collectMatches(ow, text, cls, visibleOnly, hits);
                }
            }
        }
    }

    // --------------------------------------------------------------- helpers

    private static Component resolve(Map<String, String> body) throws Exception {
        if (body.containsKey("id")) {
            return BY_ID.get(Integer.parseInt(body.get("id")));
        }
        if (body.containsKey("text")) {
            String want = body.get("text");
            final Component[] found = {null};
            onEdt(() -> {
                for (Window w : Window.getWindows()) {
                    if (w.isShowing()) {
                        Component c = firstByText(w, want);
                        if (c != null) {
                            found[0] = c;
                            return;
                        }
                    }
                }
            });
            return found[0];
        }
        return null;
    }

    private static Component firstByText(Component c, String want) {
        if (c.isShowing()) {
            String t = textOf(c);
            if (t != null && t.equals(want)) {
                return c;
            }
        }
        if (c instanceof Container ct) {
            for (Component k : ct.getComponents()) {
                Component r = firstByText(k, want);
                if (r != null) {
                    return r;
                }
            }
        }
        return null;
    }

    private static Point screenPoint(Map<String, String> body) throws Exception {
        if (body.containsKey("x") && body.containsKey("y")) {
            return new Point(Integer.parseInt(body.get("x")), Integer.parseInt(body.get("y")));
        }
        Component c = resolve(body);
        if (c == null) {
            return null;
        }
        final Point[] p = {null};
        onEdt(() -> {
            if (c.isShowing()) {
                Point loc = c.getLocationOnScreen();
                p[0] = new Point(loc.x + c.getWidth() / 2, loc.y + c.getHeight() / 2);
            }
        });
        return p[0];
    }

    private static String textOf(Component c) {
        try {
            if (c instanceof AbstractButton b) {
                return b.getText();
            }
            if (c instanceof javax.swing.JLabel l) {
                return l.getText();
            }
            if (c instanceof JTextComponent t) {
                return t.getText();
            }
            if (c instanceof Frame f) {
                return f.getTitle();
            }
            if (c instanceof java.awt.Dialog d) {
                return d.getTitle();
            }
        } catch (Exception ignore) {
        }
        return null;
    }

    private static String accessibleName(Component c) {
        try {
            if (c instanceof javax.accessibility.Accessible a) {
                AccessibleContext ac = a.getAccessibleContext();
                if (ac != null) {
                    return ac.getAccessibleName();
                }
            }
        } catch (Exception ignore) {
        }
        return null;
    }

    private static int idOf(Component c) {
        Integer id = IDS.get(c);
        if (id == null) {
            id = SEQ.getAndIncrement();
            IDS.put(c, id);
            BY_ID.put(id, c);
        }
        return id;
    }

    private static Robot robot() throws Exception {
        Robot r = robot;
        if (r == null) {
            synchronized (GuiAgent.class) {
                if (robot == null) {
                    robot = new Robot();
                    robot.setAutoDelay(20);
                }
                r = robot;
            }
        }
        return r;
    }

    private static void typeChar(Robot r, char ch) {
        boolean shift = Character.isUpperCase(ch) || "~!@#$%^&*()_+{}|:\"<>?".indexOf(ch) >= 0;
        int code = KeyEvent.getExtendedKeyCodeForChar(ch);
        if (code == KeyEvent.VK_UNDEFINED) {
            return;
        }
        if (shift) {
            r.keyPress(KeyEvent.VK_SHIFT);
        }
        try {
            r.keyPress(code);
            r.keyRelease(code);
        } catch (IllegalArgumentException ignore) {
        } finally {
            if (shift) {
                r.keyRelease(KeyEvent.VK_SHIFT);
            }
        }
    }

    private static int keyCode(String name) {
        String n = name.trim().toLowerCase();
        switch (n) {
            case "ctrl":
            case "control":
                return KeyEvent.VK_CONTROL;
            case "cmd":
            case "meta":
            case "command":
                return KeyEvent.VK_META;
            case "alt":
            case "option":
                return KeyEvent.VK_ALT;
            case "shift":
                return KeyEvent.VK_SHIFT;
            case "enter":
            case "return":
                return KeyEvent.VK_ENTER;
            case "esc":
            case "escape":
                return KeyEvent.VK_ESCAPE;
            case "tab":
                return KeyEvent.VK_TAB;
            case "space":
                return KeyEvent.VK_SPACE;
            case "backspace":
                return KeyEvent.VK_BACK_SPACE;
            case "delete":
            case "del":
                return KeyEvent.VK_DELETE;
            default:
                if (n.length() == 1) {
                    return KeyEvent.getExtendedKeyCodeForChar(n.charAt(0));
                }
                try {
                    Field f = KeyEvent.class.getField("VK_" + name.trim().toUpperCase());
                    return f.getInt(null);
                } catch (Exception e) {
                    throw new IllegalArgumentException("unknown key: " + name);
                }
        }
    }

    // --------------------------------------------------------------- plumbing

    private interface EdtTask {
        void run() throws Exception;
    }

    private static void onEdt(EdtTask task) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            task.run();
            return;
        }
        final Exception[] err = {null};
        SwingUtilities.invokeAndWait(() -> {
            try {
                task.run();
            } catch (Exception e) {
                err[0] = e;
            }
        });
        if (err[0] != null) {
            throw err[0];
        }
    }

    private interface Route {
        String handle(HttpExchange ex, Map<String, String> query) throws Exception;
    }

    private static HttpHandler wrap(Route route) {
        return ex -> {
            try {
                String body = route.handle(ex, query(ex));
                sendText(ex, 200, body);
            } catch (Exception e) {
                sendText(ex, 500, err(String.valueOf(e)));
            }
        };
    }

    private static void sendText(HttpExchange ex, int code, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(b);
        }
    }

    private static Map<String, String> query(HttpExchange ex) {
        return parseQuery(ex.getRequestURI().getRawQuery());
    }

    private static Map<String, String> parseQuery(String raw) {
        Map<String, String> m = new LinkedHashMap<>();
        if (raw == null || raw.isEmpty()) {
            return m;
        }
        for (String pair : raw.split("&")) {
            String[] kv = pair.split("=", 2);
            String k = urlDecode(kv[0]);
            String v = kv.length > 1 ? urlDecode(kv[1]) : "";
            m.put(k, v);
        }
        return m;
    }

    private static String urlDecode(String s) {
        return java.net.URLDecoder.decode(s, StandardCharsets.UTF_8);
    }

    private static String readBody(HttpExchange ex) throws IOException {
        return new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    }

    /** Minimal flat JSON object parser: supports string/number/boolean values. */
    private static Map<String, String> parseJson(String json) {
        Map<String, String> m = new LinkedHashMap<>();
        if (json == null) {
            return m;
        }
        String s = json.trim();
        if (s.startsWith("{")) {
            s = s.substring(1);
        }
        if (s.endsWith("}")) {
            s = s.substring(0, s.length() - 1);
        }
        int i = 0;
        int n = s.length();
        while (i < n) {
            while (i < n && (Character.isWhitespace(s.charAt(i)) || s.charAt(i) == ',')) {
                i++;
            }
            if (i >= n || s.charAt(i) != '"') {
                break;
            }
            StringBuilder key = new StringBuilder();
            i = readString(s, i + 1, key);
            while (i < n && (Character.isWhitespace(s.charAt(i)) || s.charAt(i) == ':')) {
                i++;
            }
            if (i >= n) {
                break;
            }
            StringBuilder val = new StringBuilder();
            if (s.charAt(i) == '"') {
                i = readString(s, i + 1, val);
            } else {
                while (i < n && s.charAt(i) != ',' && s.charAt(i) != '}') {
                    val.append(s.charAt(i++));
                }
            }
            m.put(key.toString(), val.toString().trim());
        }
        return m;
    }

    private static int readString(String s, int i, StringBuilder out) {
        int n = s.length();
        while (i < n) {
            char ch = s.charAt(i++);
            if (ch == '\\' && i < n) {
                char e = s.charAt(i++);
                switch (e) {
                    case 'n': out.append('\n'); break;
                    case 't': out.append('\t'); break;
                    case 'r': out.append('\r'); break;
                    case '"': out.append('"'); break;
                    case '\\': out.append('\\'); break;
                    case '/': out.append('/'); break;
                    case 'u':
                        out.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                        break;
                    default: out.append(e);
                }
            } else if (ch == '"') {
                return i;
            } else {
                out.append(ch);
            }
        }
        return i;
    }

    private static int intOr(Map<String, String> m, String k, int dflt) {
        try {
            return m.containsKey(k) ? Integer.parseInt(m.get(k).trim()) : dflt;
        } catch (NumberFormatException e) {
            return dflt;
        }
    }

    private static String rect(Rectangle b) {
        return "{\"x\":" + b.x + ",\"y\":" + b.y + ",\"w\":" + b.width + ",\"h\":" + b.height + "}";
    }

    private static String err(String msg) {
        return "{\"ok\":false,\"error\":\"" + esc(msg) + "\"}";
    }

    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    private GuiAgent() {
    }
}
