package ghidra.app.plugin.core.decompiler.taint.ctadl.model;
public final class IndexFreshness {
  private boolean stale = true;
  public boolean isStale(){ return stale; }
  public void markIndexed(){ stale = false; }
  public void onModelChanged(TaintModel m){ if (m.destination()==TaintModel.Destination.INDEX) stale = true; }
  public void onModelSetStructurallyChanged(){ stale = true; }
}
