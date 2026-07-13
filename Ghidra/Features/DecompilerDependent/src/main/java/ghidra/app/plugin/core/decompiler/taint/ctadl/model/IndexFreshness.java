package ghidra.app.plugin.core.decompiler.taint.ctadl.model;
/**
 * Tracks whether the on-disk program index reflects the current propagation (index-time) models.
 * "Stale" means a propagation model has been added/toggled/deleted since the last successful index
 * and the index must be rebuilt for the change to take effect. Starts in sync (not stale): a fresh
 * tracker assumes the index matches; index-relevant model changes flip it stale, and a successful
 * re-index ({@link #markIndexed}) clears it. Source/sink models are query-time and never affect it.
 */
public final class IndexFreshness {
  private boolean stale = false;
  public boolean isStale(){ return stale; }
  public void markIndexed(){ stale = false; }
  public void onModelChanged(TaintModel m){ if (m.destination()==TaintModel.Destination.INDEX) stale = true; }
  public void onModelSetStructurallyChanged(){ stale = true; }
}
