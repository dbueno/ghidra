package ghidra.app.plugin.core.decompiler.taint.ctadl.model;
import java.util.List;
public class ModelJsonlWriterTest {
  static int fails=0;
  static void check(String n, boolean c){ System.out.println((c?"ok: ":"FAIL: ")+n); if(!c) fails++; }
  public static void main(String[] a){
    var src = TaintModel.source(List.of("recv","recvfrom"), "Argument(1).deref", "user_input");
    var snk = TaintModel.sink(List.of("strcpy"), "Argument(1).deref", "buffer_overflow");
    var prop = TaintModel.propagation(List.of("memcpy"), "Argument(1).deref", "Argument(0).deref");
    var disabled = TaintModel.sink(List.of("system"), "Argument(0).deref", "command_injection");
    disabled.setEnabled(false);
    String q = ModelJsonlWriter.toJsonl(List.of(src, snk, prop, disabled), TaintModel.Destination.QUERY);
    check("query has recv source", q.contains("\"names\":[\"recv\",\"recvfrom\"]") && q.contains("\"sources\":[{\"port\":\"Argument(1).deref\",\"kind\":\"user_input\"}]"));
    check("query has strcpy sink", q.contains("\"sinks\":[{\"port\":\"Argument(1).deref\",\"kind\":\"buffer_overflow\"}]"));
    check("query excludes propagation", !q.contains("\"propagation\""));
    check("query excludes disabled system", !q.contains("system"));
    check("query is 2 lines", q.strip().split("\n").length==2);
    String ix = ModelJsonlWriter.toJsonl(List.of(src, snk, prop), TaintModel.Destination.INDEX);
    check("index has memcpy prop", ix.contains("\"propagation\":[{\"input\":\"Argument(1).deref\",\"output\":\"Argument(0).deref\"}]"));
    check("index excludes sources/sinks", !ix.contains("\"sources\"") && !ix.contains("\"sinks\""));
    check("empty when none match", ModelJsonlWriter.toJsonl(List.of(src), TaintModel.Destination.INDEX).isEmpty());
    if(fails>0) System.exit(1);
  }
}
