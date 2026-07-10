package ghidra.app.plugin.core.decompiler.taint.ctadl.engine;
import java.util.ArrayList;import java.util.List;import java.util.Map;
public final class NativeCtadlCommand {
  private NativeCtadlCommand(){}
  public static List<String> importCmd(String engine, String prog, String factsDir){
    return List.of(engine,"import","-l","pcode","-n",prog,factsDir);
  }
  public static List<String> indexCmd(String engine, String prog, String propagationJsonl){
    List<String> c = new ArrayList<>(List.of(engine,"index",prog,prog));
    if (propagationJsonl != null) { c.add("-m"); c.add(propagationJsonl); }
    return c;
  }
  public static List<String> queryCmd(String engine, String prog, String srcSinkJsonl, String outSarif){
    return List.of(engine,"query",prog,"-m",srcSinkJsonl,"-o",outSarif,"--sarif-profile","debug");
  }
  public static Map<String,String> storeEnv(String storeDir){
    return storeDir == null ? Map.of() : Map.of("XDG_STATE_HOME", storeDir);
  }
}
