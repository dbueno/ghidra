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

	/**
	 * Returns the ports of {@code f}: a {@code Return} option (unless the return type is
	 * void), followed by one {@code Argument(i)} option per parameter. Pointer-typed
	 * ports are flagged so the picker can offer {@code .deref} (contents) vs. the raw
	 * pointer.
	 */
	public static List<PortOption> portsOf(Function f) {
		List<PortOption> out = new ArrayList<>();
		DataType ret = f.getReturnType();
		if (ret != null && !(ret instanceof VoidDataType)) {
			out.add(new PortOption("return: " + ret.getName(), "Return", ret instanceof Pointer, "return"));
		}
		Parameter[] ps = f.getParameters();
		for (int i = 0; i < ps.length; i++) {
			DataType pt = ps[i].getDataType();
			String nm = ps[i].getName();
			out.add(new PortOption("arg" + i + ": " + pt.getName() + " " + nm,
				"Argument(" + i + ")", pt instanceof Pointer, nm));
		}
		return out;
	}
}
