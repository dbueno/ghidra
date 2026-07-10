/* ###
 * IP: GHIDRA
 */
package ghidra.app.plugin.core.decompiler.taint.ctadl;

import ghidra.app.plugin.core.decompiler.taint.ctadl.engine.NativeCtadlCommand;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.ProcessBuilder.Redirect;
import java.util.List;
import java.util.function.Consumer;

/**
 * Runs the native ctadl pipeline (<code>import → index</code>, then <code>query</code>)
 * as OS processes, applying the store location via the <code>XDG_STATE_HOME</code>
 * environment variable. Argv is built by {@link NativeCtadlCommand}; this class owns
 * only the process mechanics (multi-phase sequencing, env, stdout draining, exit codes).
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

	private static int run(List<String> argv, String storeDir, File workDir, Consumer<String> log)
			throws IOException, InterruptedException {
		ProcessBuilder pb = new ProcessBuilder(argv);
		if (workDir != null) {
			pb.directory(workDir);
		}
		// Store location: only override XDG_STATE_HOME when a store dir is configured;
		// otherwise ctadl uses its own default ($XDG_STATE_HOME/ctadl).
		String store = (storeDir == null || storeDir.isBlank()) ? null : storeDir;
		pb.environment().putAll(NativeCtadlCommand.storeEnv(store));
		pb.redirectError(Redirect.INHERIT);
		log.accept("ctadl: " + String.join(" ", argv));
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
				new File(factsDir), log);
			if (ic != 0) {
				log.accept("ctadl import failed (exit " + ic + ")");
				return false;
			}
			int xc = run(NativeCtadlCommand.indexCmd(engine, prog, propagationJsonl), storeDir,
				new File(factsDir), log);
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
	 * @return true iff the query exited 0.
	 */
	public static boolean query(String engine, String storeDir, String prog, String queryModelFile,
			String outSarif, Consumer<String> log) {
		try {
			int qc = run(NativeCtadlCommand.queryCmd(engine, prog, queryModelFile, outSarif),
				storeDir, null, log);
			if (qc != 0) {
				log.accept("ctadl query failed (exit " + qc + ")");
				return false;
			}
			return true;
		}
		catch (IOException | InterruptedException e) {
			log.accept("ctadl query error: " + e);
			return false;
		}
	}
}
