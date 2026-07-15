/* ###
 * IP: GHIDRA
 */
package ghidra.app.plugin.core.decompiler.taint.ctadl;

import ghidra.app.plugin.core.decompiler.taint.ctadl.model.PortOption;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;

import java.util.ArrayList;
import java.util.List;

/**
 * Resolves a Ghidra {@link Function} to the taint {@link PortOption}s an analyst can
 * mark (its return value and each parameter), and resolves thunks to their target.
 * The producer half of the function-centric modeling flow: a marked function plus a
 * chosen port becomes a {@code find:"methods"} generator.
 */
public final class FunctionPortResolver {
	private FunctionPortResolver() {
	}

	/**
	 * If {@code f} is a thunk (e.g. a PLT stub for an imported function), returns the
	 * thunked target so the model is authored against the real function; otherwise
	 * returns {@code f}.
	 */
	public static Function resolveTarget(Function f) {
		return (f != null && f.isThunk()) ? f.getThunkedFunction(true) : f;
	}

	/** Ports of {@code f} using only its committed formal parameters (no decompiler fallback). */
	public static List<PortOption> portsOf(Function f) {
		return portsOf(f, null);
	}

	/**
	 * Returns the ports of {@code f}: a {@code Return} option (unless the return type is
	 * void), followed by one {@code Argument(i)} option per parameter. Pointer-typed
	 * ports are flagged so the picker can offer {@code .deref} (contents) vs. the raw
	 * pointer.
	 *
	 * <p>Parameters come from {@code f.getParameters()} (Ghidra's committed formal
	 * parameters). When those are empty — common for user code such as {@code main} whose
	 * signature has not been committed — and {@code hf} is supplied, the ports fall back to
	 * the decompiler's inferred parameters, so the picker still offers argument ports without
	 * a manual <em>Commit Params/Return</em>. Pass {@code hf == null} to disable the fallback.
	 */
	public static List<PortOption> portsOf(Function f, HighFunction hf) {
		List<PortOption> out = new ArrayList<>();
		DataType ret = f.getReturnType();
		if (ret != null && !(ret instanceof VoidDataType)) {
			out.add(new PortOption("return: " + ret.getName(), "Return", ret instanceof Pointer, "return"));
		}
		Parameter[] ps = f.getParameters();
		if (ps.length > 0) {
			for (int i = 0; i < ps.length; i++) {
				DataType pt = ps[i].getDataType();
				out.add(argPort(i, pt.getName(), ps[i].getName(), pt instanceof Pointer));
			}
		}
		else if (hf != null) {
			LocalSymbolMap lsm = hf.getLocalSymbolMap();
			int n = lsm.getNumParams();
			for (int i = 0; i < n; i++) {
				HighSymbol sym = lsm.getParamSymbol(i);
				DataType pt = sym.getDataType();
				String tn = pt != null ? pt.getName() : "undefined";
				out.add(argPort(i, tn, sym.getName(), pt instanceof Pointer));
			}
		}
		return out;
	}

	private static PortOption argPort(int i, String typeName, String name, boolean pointer) {
		return new PortOption("arg" + i + ": " + typeName + " " + name,
			"Argument(" + i + ")", pointer, name);
	}
}
