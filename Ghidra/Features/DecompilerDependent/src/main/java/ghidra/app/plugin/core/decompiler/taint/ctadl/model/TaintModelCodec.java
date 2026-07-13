package ghidra.app.plugin.core.decompiler.taint.ctadl.model;
import java.util.ArrayList;import java.util.List;
public final class TaintModelCodec {
  private TaintModelCodec(){}
  private static final String US = "";
  public static String encode(List<TaintModel> ms){
    StringBuilder sb = new StringBuilder();
    for (TaintModel m : ms){
      sb.append(m.role().name()).append(US)
        .append(String.join(",", m.functionNames())).append(US)
        .append(nz(m.port())).append(US).append(nz(m.kind())).append(US)
        .append(nz(m.inputPort())).append(US).append(nz(m.outputPort())).append(US)
        .append(m.enabled()).append(US)
        .append(nz(m.portDisplay())).append(US)
        .append(nz(m.inputDisplay())).append(US)
        .append(nz(m.outputDisplay())).append('\n');
    }
    return sb.toString();
  }
  public static List<TaintModel> decode(String s){
    List<TaintModel> out = new ArrayList<>();
    if (s == null || s.isEmpty()) return out;
    for (String line : s.split("\n")){
      if (line.isEmpty()) continue;
      String[] f = line.split(US, -1);
      if (f.length < 7) continue; // guard truncated rows
      List<String> names = f[1].isEmpty() ? List.of() : List.of(f[1].split(","));
      String pd = f.length > 7 ? emptyToNull(f[7]) : null;
      String id = f.length > 8 ? emptyToNull(f[8]) : null;
      String od = f.length > 9 ? emptyToNull(f[9]) : null;
      TaintModel m = switch (TaintModel.Role.valueOf(f[0])){
        case SOURCE -> TaintModel.source(names, f[2], f[3], pd);
        case SINK   -> TaintModel.sink(names, f[2], f[3], pd);
        case PROPAGATION -> TaintModel.propagation(names, f[4], f[5], id, od);
      };
      m.setEnabled(Boolean.parseBoolean(f[6]));
      out.add(m);
    }
    return out;
  }
  private static String nz(String s){ return s == null ? "" : s; }
  private static String emptyToNull(String s){ return s == null || s.isEmpty() ? null : s; }
}
