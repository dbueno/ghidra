package ghidra.app.plugin.core.decompiler.taint.ctadl.model;
public final class PortOption {
  private final String label; private final String basePort; private final boolean pointer;
  public PortOption(String label, String basePort, boolean pointer){ this.label=label; this.basePort=basePort; this.pointer=pointer; }
  public String label(){ return label; }
  public String basePort(){ return basePort; }
  public boolean pointer(){ return pointer; }
  public String portString(boolean deref){ return deref ? basePort + ".deref" : basePort; }
}
