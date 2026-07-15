/* ###
 * IP: GHIDRA
 */
package ghidra.app.plugin.core.decompiler.taint.actions;

import java.util.List;

import docking.action.MenuData;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompiler.taint.TaintPlugin;
import ghidra.app.plugin.core.decompiler.taint.ctadl.CTADLTaintState;
import ghidra.app.plugin.core.decompiler.taint.ctadl.FunctionPortResolver;
import ghidra.app.plugin.core.decompiler.taint.ctadl.TaintModelDialog;
import ghidra.app.plugin.core.decompiler.taint.ctadl.model.TaintModel;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.symbol.Reference;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.UndefinedFunction;

/**
 * Right-click a token in the decompiler and model taint at a <b>function boundary</b>: the
 * callee if the token is a call, otherwise the enclosing function. Opens {@link TaintModelDialog}
 * to pick source/sink ports (and optional propagation) and adds the authored
 * {@link TaintModel}s to the ctadl state, which the query emits. This is the function-centric
 * replacement for interior-varnode marking.
 */
public class TaintModelFromFunctionAction extends TaintAbstractDecompilerAction {

	private final TaintPlugin plugin;

	public TaintModelFromFunctionAction(TaintPlugin plugin) {
		super("Model Taint For Function");
		setHelpLocation(new HelpLocation(TaintPlugin.HELP_LOCATION, "TaintModelFunction"));
		setPopupMenuData(new MenuData(new String[] { "Taint", "Model function ports…" }, "Decompile"));
		this.plugin = plugin;
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		if (!(plugin.getTaintState() instanceof CTADLTaintState)) {
			return false;
		}
		Function enclosing = context.getFunction();
		return enclosing != null && !(enclosing instanceof UndefinedFunction);
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		Program program = context.getProgram();
		Function target = calleeFromToken(context.getTokenAtCursor(), program);
		HighFunction hf = null;
		if (target == null) {
			// Enclosing function: the decompiler's HighFunction describes it, so hand it to the
			// picker — its ports fall back to inferred parameters when the signature is
			// uncommitted (e.g. user code like main). A resolved callee keeps hf == null (the
			// HighFunction is the caller's, and library callees carry committed signatures).
			target = context.getFunction();
			hf = context.getHighFunction();
		}
		if (target == null) {
			return;
		}

		TaintModelDialog dialog = new TaintModelDialog(target, hf);
		context.getTool().showDialog(dialog);
		if (dialog.isCancelled() || dialog.getResult().isEmpty()) {
			return;
		}

		List<TaintModel> models = dialog.getResult();
		((CTADLTaintState) plugin.getTaintState()).addModels(models);
		plugin.showTaintModels();
		plugin.consoleMessage("Added " + models.size() + " taint model(s) for " +
			FunctionPortResolver.resolveTarget(target).getName() +
			"; run 'Run default taint query' to apply.");

		// Propagation models are index-time: warn once (per picker session) that a re-index is
		// needed. Source/sink models are query-time and need no re-index.
		boolean anyPropagation = models.stream()
				.anyMatch(m -> m.role() == TaintModel.Role.PROPAGATION);
		if (anyPropagation) {
			Msg.showWarn(this, null, "Re-index required", CTADLTaintState.REINDEX_WARNING);
		}
	}

	/**
	 * If {@code token} is a call's function-name token, resolve the callee via the call
	 * reference from the token's address; otherwise null (caller falls back to the enclosing
	 * function).
	 */
	private Function calleeFromToken(ClangToken token, Program program) {
		if (!(token instanceof ClangFuncNameToken) || program == null) {
			return null;
		}
		Address addr = token.getMinAddress();
		if (addr == null) {
			return null;
		}
		for (Reference r : program.getReferenceManager().getReferencesFrom(addr)) {
			if (r.getReferenceType().isCall()) {
				Function f = program.getFunctionManager().getFunctionAt(r.getToAddress());
				if (f != null) {
					return f;
				}
			}
		}
		return null;
	}
}
