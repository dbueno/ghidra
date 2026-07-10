package ghidra.app.plugin.core.decompiler.taint.ctadl.model;
import java.util.List;
public class TaintModelCodecTest {
  static int fails=0;
  static void check(String n, boolean c){ System.out.println((c?"ok: ":"FAIL: ")+n); if(!c) fails++; }
  public static void main(String[] a){
    var src = TaintModel.source(List.of("recv"), "Argument(1).deref", "user_input");
    var prop = TaintModel.propagation(List.of("memcpy"), "Argument(1).deref", "Argument(0).deref");
    prop.setEnabled(false);
    String enc = TaintModelCodec.encode(List.of(src, prop));
    List<TaintModel> back = TaintModelCodec.decode(enc);
    check("count", back.size()==2);
    check("src role", back.get(0).role()==TaintModel.Role.SOURCE);
    check("src names", back.get(0).functionNames().equals(List.of("recv")));
    check("src port", back.get(0).port().equals("Argument(1).deref"));
    check("src enabled", back.get(0).enabled());
    check("prop role", back.get(1).role()==TaintModel.Role.PROPAGATION);
    check("prop in/out", back.get(1).inputPort().equals("Argument(1).deref") && back.get(1).outputPort().equals("Argument(0).deref"));
    check("prop disabled preserved", !back.get(1).enabled());
    check("empty round-trip", TaintModelCodec.decode(TaintModelCodec.encode(List.of())).isEmpty());
    if(fails>0) System.exit(1);
  }
}
