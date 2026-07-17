/* ###
 * IP: GHIDRA
 */
package ghidra.app.plugin.core.decompiler.taint.ctadl;

import ghidra.app.plugin.core.decompiler.taint.ctadl.engine.MatchCount;
import ghidra.app.plugin.core.decompiler.taint.ctadl.engine.NativeCtadlCommand;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.ProcessBuilder.Redirect;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Runs the native ctadl pipeline (<code>import → index</code>, then <code>query</code>)
 * as OS processes, applying the store location via the global <code>--store</code>
 * flag. Argv is built by {@link NativeCtadlCommand}; this class owns
 * only the process mechanics (multi-phase sequencing, stdout draining, exit codes).
 */
public final class NativeCtadlRunner {
	private NativeCtadlRunner() {
	}

	/** Sanitize a program name into a store-safe import/project name. */
	public static String sanitizeName(String programName) {
		if (programName == null || programName.isBlank()) {
			return "program";
		}
		return programName.replaceAll("[^A-Za-z0-9._-]", "_");
	}

	private static int run(List<String> argv, String storeDir, File workDir, boolean mergeStderr,
			Consumer<String> log) throws IOException, InterruptedException {
		// Store location: when a store dir is configured, pass it to ctadl via the global
		// --store flag inserted right after the engine executable
		// (ctadl --store <dir> <subcommand> ...). Unlike XDG_STATE_HOME, --store is used
		// directly as the store root — no 'ctadl' subdirectory is appended. When unset, ctadl
		// uses its own default ($XDG_STATE_HOME/ctadl).
		List<String> storeArgs = NativeCtadlCommand.storeArgs(storeDir);
		List<String> fullArgv;
		if (storeArgs.isEmpty()) {
			fullArgv = argv;
		}
		else {
			fullArgv = new ArrayList<>(argv);
			fullArgv.addAll(1, storeArgs);
		}
		ProcessBuilder pb = new ProcessBuilder(fullArgv);
		if (workDir != null) {
			pb.directory(workDir);
		}
		if (mergeStderr) {
			// Fold stderr into stdout so the reader loop sees engine diagnostics — including the
			// "Matched N sources and M sinks" line. Used for the query phase only.
			pb.redirectErrorStream(true);
		}
		else {
			pb.redirectError(Redirect.INHERIT);
		}
		log.accept("ctadl: " + String.join(" ", fullArgv));
		Process p = pb.start();
		try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
			String line;
			while ((line = r.readLine()) != null) {
				log.accept(line);
			}
		}
		return p.waitFor();
	}

	/**
	 * Import an exported facts directory (Ghidra is skipped via the facts-dir
	 * short-circuit) and index it under {@code prog}. {@code propagationJsonl} is an
	 * optional index-time model file ({@code null} when there are no propagation models).
	 *
	 * @return true iff both phases exited 0.
	 */
	public static boolean importAndIndex(String engine, String storeDir, String prog,
			String factsDir, String propagationJsonl, Consumer<String> log) {
		try {
			int ic = run(NativeCtadlCommand.importCmd(engine, prog, factsDir), storeDir,
				new File(factsDir), false, log);
			if (ic != 0) {
				log.accept("ctadl import failed (exit " + ic + ")");
				return false;
			}
			int xc = run(NativeCtadlCommand.indexCmd(engine, prog, propagationJsonl), storeDir,
				new File(factsDir), false, log);
			if (xc != 0) {
				log.accept("ctadl index failed (exit " + xc + ")");
				return false;
			}
			return true;
		}
		catch (IOException | InterruptedException e) {
			log.accept("ctadl import/index error: " + e);
			return false;
		}
	}

	/**
	 * Run a query for {@code prog} using the source/sink model file {@code queryModelFile},
	 * writing SARIF (debug profile) to {@code outSarif}.
	 *
	 * <p>stderr is merged into stdout ({@code mergeStderr=true}) so the engine's
	 * {@code "Matched N sources and M sinks"} line reaches the plugin console. When the
	 * count shows 0 on either side an advisory note is appended explaining that no taint
	 * paths are possible and suggesting a model check.
	 *
	 * @return true iff the query exited 0.
	 */
	public static boolean query(String engine, String storeDir, String prog, String queryModelFile,
			String outSarif, Consumer<String> log) {
		try {
			// stderr is merged (mergeStderr=true) so "Matched N sources and M sinks" reaches the
			// console; sniff it to advise when a query matched 0 sources or 0 sinks.
			MatchCount[] seen = { null };
			Consumer<String> sniff = line -> {
				MatchCount.parse(line).ifPresent(mc -> seen[0] = mc);
				log.accept(line);
			};
			int qc = run(NativeCtadlCommand.queryCmd(engine, prog, queryModelFile, outSarif),
				storeDir, null, true, sniff);
			if (qc != 0) {
				log.accept("ctadl query failed (exit " + qc + ")");
				return false;
			}
			if (seen[0] != null && seen[0].isEmptyMatch()) {
				log.accept("Note: the query matched " + seen[0].sources() + " source(s) and " +
					seen[0].sinks() + " sink(s); with 0 on either side there can be no taint paths — " +
					"check that your source/sink models name functions present in this program.");
			}
			return true;
		}
		catch (IOException | InterruptedException e) {
			log.accept("ctadl query error: " + e);
			return false;
		}
	}
}
