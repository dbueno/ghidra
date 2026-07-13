package ghidra.app.plugin.core.decompiler.taint.ctadl.model;
public final class PortOption {
  private final String label; private final String basePort; private final boolean pointer;
  private final String displayName;
  public PortOption(String label, String basePort, boolean pointer){ this(label, basePort, pointer, basePort); }
  public PortOption(String label, String basePort, boolean pointer, String displayName){
    this.label=label; this.basePort=basePort; this.pointer=pointer; this.displayName=displayName; }
  public String label(){ return label; }
  public String basePort(){ return basePort; }
  public boolean pointer(){ return pointer; }
  public String displayName(){ return displayName; }
  public String portString(boolean deref){ return deref ? basePort + ".deref" : basePort; }
  public String displayPort(boolean deref){ return (deref ? "*" : "") + displayName; }
}
