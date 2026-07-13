/* ###
 * IP: GHIDRA
 */
package ghidra.app.plugin.core.decompiler.taint.ctadl.engine;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
/**
 * Parses the engine's per-query stderr line {@code "Matched N sources and M sinks"}
 * (ctadl-ascent cli/mod.rs) so the plugin can surface the count and advise when a query
 * matched 0 sources or 0 sinks — i.e. a model that named nothing present in this program.
 */
public record MatchCount(int sources, int sinks) {
  private static final Pattern P = Pattern.compile("Matched (\\d+) sources and (\\d+) sinks");
  /** Parse one engine output line; empty when it is not a match-count line. Null-safe. */
  public static Optional<MatchCount> parse(String line) {
    if (line == null) {
      return Optional.empty();
    }
    Matcher m = P.matcher(line);
    return m.find()
        ? Optional.of(new MatchCount(Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2))))
        : Optional.empty();
  }
  /** True when the query matched no sources or no sinks (so it can yield no taint paths). */
  public boolean isEmptyMatch() {
    return sources == 0 || sinks == 0;
  }
}
