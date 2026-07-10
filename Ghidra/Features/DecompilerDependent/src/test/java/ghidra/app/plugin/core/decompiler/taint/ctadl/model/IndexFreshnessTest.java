package ghidra.app.plugin.core.decompiler.taint.ctadl.model;
import java.util.List;
public class IndexFreshnessTest {
  static int fails=0;
  static void check(String n, boolean c){ System.out.println((c?"ok: ":"FAIL: ")+n); if(!c) fails++; }
  public static void main(String[] a){
    IndexFreshness f = new IndexFreshness();
    check("starts stale", f.isStale());
    f.markIndexed(); check("clean after index", !f.isStale());
    f.onModelChanged(TaintModel.source(List.of("recv"),"Argument(1).deref","user_input"));
    check("source change does not restale", !f.isStale());
    f.onModelChanged(TaintModel.propagation(List.of("memcpy"),"Argument(1).deref","Argument(0).deref"));
    check("propagation change restales", f.isStale());
    f.markIndexed();
    f.onModelSetStructurallyChanged();
    check("structural change restales", f.isStale());
    if(fails>0) System.exit(1);
  }
}
