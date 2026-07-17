package ghidra.app.plugin.core.decompiler.taint.ctadl.engine;
import java.util.ArrayList;import java.util.List;
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
  /**
   * The global {@code --store <dir>} flag passing the configured store location to ctadl, or an
   * empty list when no store is configured (ctadl then uses its default $XDG_STATE_HOME/ctadl).
   * Unlike setting XDG_STATE_HOME, {@code --store} is used directly as the store root — ctadl does
   * not append a {@code ctadl} subdirectory.
   */
  public static List<String> storeArgs(String storeDir){
    return storeDir == null || storeDir.isBlank() ? List.of() : List.of("--store", storeDir);
  }
}
