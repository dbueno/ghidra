package ghidra.app.plugin.core.decompiler.taint.ctadl.model;
import java.util.List;
public final class TaintModel {
  public enum Role { SOURCE, SINK, PROPAGATION }
  public enum Destination { INDEX, QUERY }
  private final List<String> functionNames;
  private final Role role;
  private final String port;       // source/sink
  private final String kind;       // source/sink
  private final String inputPort;  // propagation
  private final String outputPort; // propagation
  private boolean enabled = true;
  private TaintModel(List<String> fns, Role r, String port, String kind, String in, String out) {
    this.functionNames = List.copyOf(fns); this.role = r;
    this.port = port; this.kind = kind; this.inputPort = in; this.outputPort = out;
  }
  public static TaintModel source(List<String> fns, String port, String kind){ return new TaintModel(fns, Role.SOURCE, port, kind, null, null); }
  public static TaintModel sink(List<String> fns, String port, String kind){ return new TaintModel(fns, Role.SINK, port, kind, null, null); }
  public static TaintModel propagation(List<String> fns, String in, String out){ return new TaintModel(fns, Role.PROPAGATION, null, null, in, out); }
  public List<String> functionNames(){ return functionNames; }
  public Role role(){ return role; }
  public String port(){ return port; }
  public String kind(){ return kind; }
  public String inputPort(){ return inputPort; }
  public String outputPort(){ return outputPort; }
  public boolean enabled(){ return enabled; }
  public void setEnabled(boolean e){ this.enabled = e; }
  public Destination destination(){ return role == Role.PROPAGATION ? Destination.INDEX : Destination.QUERY; }
}
