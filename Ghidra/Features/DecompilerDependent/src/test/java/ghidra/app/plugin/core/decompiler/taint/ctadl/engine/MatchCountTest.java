/* ###
 * IP: GHIDRA
 */
package ghidra.app.plugin.core.decompiler.taint.ctadl.engine;
import java.util.Optional;
public class MatchCountTest {
  static int fails=0;
  static void check(String n, boolean c){ System.out.println((c?"ok: ":"FAIL: ")+n); if(!c) fails++; }
  public static void main(String[] a){
    Optional<MatchCount> mc = MatchCount.parse("Matched 4 sources and 5 sinks");
    check("present", mc.isPresent());
    check("sources", mc.get().sources()==4);
    check("sinks", mc.get().sinks()==5);
    check("not empty", !mc.get().isEmptyMatch());
    check("zero sources => empty", MatchCount.parse("Matched 0 sources and 5 sinks").get().isEmptyMatch());
    check("zero sinks => empty", MatchCount.parse("Matched 3 sources and 0 sinks").get().isEmptyMatch());
    check("both zero => empty", MatchCount.parse("Matched 0 sources and 0 sinks").get().isEmptyMatch());
    check("embedded in longer line", MatchCount.parse("ctadl: Matched 1 sources and 2 sinks").isPresent());
    check("non-match line empty", MatchCount.parse("query complete").isEmpty());
    check("null safe", MatchCount.parse(null).isEmpty());
    if(fails>0) System.exit(1);
  }
}
