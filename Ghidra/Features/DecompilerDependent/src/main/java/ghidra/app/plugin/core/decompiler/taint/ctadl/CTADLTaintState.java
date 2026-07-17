/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.decompiler.taint.ctadl;

import java.io.File;
import java.io.FileInputStream;
import java.io.PrintWriter;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.app.plugin.core.decompiler.taint.CreateTargetIndexTask;
import generic.jar.ResourceFile;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.decompiler.taint.*;
import ghidra.app.plugin.core.decompiler.taint.TaintPlugin.TaintDirection;
import ghidra.app.plugin.core.osgi.BundleHost;
import ghidra.app.script.*;
import ghidra.app.plugin.core.decompiler.taint.ctadl.model.IndexFreshness;
import ghidra.app.plugin.core.decompiler.taint.ctadl.model.TaintModel;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

/**
 * Container for all the decompiler elements the users "selects" via the menu.
 * This data is used to build queries.
 */
public class CTADLTaintState extends AbstractTaintState {

	/**
	 * Function-centric models authored via the picker dialog ({@link TaintModelDialog}).
	 * Source/sink models here are emitted into the query file alongside the legacy marks;
	 * this is the seed of the models set the manager panel will own.
	 */
	private final List<TaintModel> authoredModels = new ArrayList<>();

	/**
	 * Tracks whether the on-disk index reflects the current propagation models. Propagation
	 * models are applied at index time ({@code ctadl index -m}), so changing them (add, toggle,
	 * delete) marks the index stale until {@link #getIndexFreshness()}.{@code markIndexed()} is
	 * called after a successful re-index (see {@code CreateTargetIndexTask}). Source/sink models
	 * are query-time and never affect freshness.
	 */
	private final IndexFreshness indexFreshness = new IndexFreshness();

	/** Shown when a propagation-model change requires re-running the index to take effect. */
	public static final String REINDEX_WARNING =
		"Propagation models are applied when the program index is built.\n" +
			"Re-run 'Initialize Program Index' (Create Index) for this change to take effect.";

	public CTADLTaintState(TaintPlugin plugin) {
		super(plugin);
		ENGINE_NAME = "ctadl";
		// The rust/Ascent CTADL engine keeps its index in a directory-based
		// parquet store under the output directory, not a single `ctadlir.db`
		// file. Disable the base class's index-DB-file existence gate (which would
		// otherwise abort every query); `Create Index` still builds the store.
		usesIndex = false;
	}

	/**
	 * Runs a query against the native ctadl store: writes the source/sink model file,
	 * invokes {@code ctadl query <prog> -m <model> -o <out.sarif> --sarif-profile debug}
	 * (store via {@code XDG_STATE_HOME}), then loads the resulting SARIF file through the
	 * same handler path the legacy stdout flow used. Replaces the base class's
	 * single-process, stdout-reading {@code queryIndex}.
	 */
	@Override
	public boolean queryIndex(Program program, PluginTool tool, QueryType queryType) {
		if (queryType.equals(QueryType.SRCSINK) && !isValid()) {
			Msg.showWarn(this, tool.getActiveWindow(), getName() + " Query Warning",
				getName() + " query cannot be performed because there are no sources or sinks.");
			return false;
		}

		taintOptions = plugin.getOptions();
		try {
			String outputDir = taintOptions.getTaintOutputDirectory();

			// Resolve the source/sink model file for this query.
			File queryFile;
			if (queryType.equals(QueryType.CUSTOM)) {
				GhidraFileChooser chooser =
					new GhidraFileChooser(plugin.getProvider().getComponent());
				chooser.setCurrentDirectory(Path.of(outputDir).toFile());
				queryFile = chooser.getSelectedFile();
				if (queryFile == null) {
					return false;
				}
			}
			else {
				// SRCSINK and DEFAULT both run the currently-active marks; writeQueryFile
				// emits a {model_generators:[...]} document, which the native -m accepts.
				queryFile = Path.of(outputDir, taintOptions.getTaintQueryDLName()).toFile();
				writeQueryFile(queryFile);
			}

			return runNativeQuery(program, tool, queryFile, "");
		}
		catch (Exception e) {
			Msg.error(this, "Problems running query: " + e);
			return false;
		}
	}

	/**
	 * Runs a <b>forward-exploration</b> query: seeds the enabled source(s) and pairs them with a
	 * synthetic catch-all sink so the engine's meet-in-the-middle materializes each source's full
	 * forward taint cone (see {@link #writeExplorationQueryFile}). No sink authoring is required.
	 * Results surface as {@code C0002} tainted-instructions — apply the "All tainted" highlight
	 * scope to see the cone. Returns false (with a warning) if there is no enabled source to explore.
	 */
	public boolean queryForwardExploration(Program program, PluginTool tool) {
		taintOptions = plugin.getOptions();
		try {
			File queryFile = Path.of(taintOptions.getTaintOutputDirectory(),
				"ctadl-explore-" + NativeCtadlRunner.sanitizeName(program.getName()) + ".json")
					.toFile();
			if (!writeExplorationQueryFile(queryFile)) {
				Msg.showWarn(this, tool.getActiveWindow(), getName() + " Exploration",
					"No enabled source to explore. Author at least one source model (or mark a " +
						"source), then retry.");
				return false;
			}
			boolean ok = runNativeQuery(program, tool, queryFile, "-explore");
			if (ok) {
				plugin.consoleMessage("Forward exploration complete — apply the 'All tainted' " +
					"highlight scope to see where taint flows from your source(s).");
			}
			return ok;
		}
		catch (Exception e) {
			Msg.error(this, "Problems running exploration query: " + e);
			return false;
		}
	}

	/**
	 * Runs a <b>backward-exploration</b> query: seeds the enabled sink(s) and pairs them with a
	 * synthetic catch-all source so the engine's meet-in-the-middle materializes each sink's full
	 * backward taint cone (see {@link #writeBackwardExplorationQueryFile}). No source authoring is
	 * required. Results surface as {@code C0002} tainted-instructions — apply the "All tainted"
	 * highlight scope to see the cone. Returns false (with a warning) if there is no enabled sink.
	 */
	public boolean queryBackwardExploration(Program program, PluginTool tool) {
		taintOptions = plugin.getOptions();
		try {
			File queryFile = Path.of(taintOptions.getTaintOutputDirectory(),
				"ctadl-explore-bwd-" + NativeCtadlRunner.sanitizeName(program.getName()) + ".json")
						.toFile();
			if (!writeBackwardExplorationQueryFile(queryFile)) {
				Msg.showWarn(this, tool.getActiveWindow(), getName() + " Exploration",
					"No enabled sink to explore. Mark a sink (or enable a sink model), then retry.");
				return false;
			}
			boolean ok = runNativeQuery(program, tool, queryFile, "-explore-bwd");
			if (ok) {
				plugin.consoleMessage("Backward exploration complete — apply the 'All tainted' " +
					"highlight scope to see what flows into your sink(s).");
			}
			return ok;
		}
		catch (Exception e) {
			Msg.error(this, "Problems running backward exploration query: " + e);
			return false;
		}
	}

	/**
	 * Shared native-query core used by the source/sink query ({@link #queryIndex}) and forward
	 * exploration ({@link #queryForwardExploration}): resolve the engine, ensure the program is
	 * indexed (offering to index if not), run
	 * {@code ctadl query <prog> -m <queryFile> -o <sarif> --sarif-profile debug}, then load the
	 * resulting SARIF into the data frame. {@code outputTag} is inserted into the output SARIF name
	 * ({@code <prog><outputTag>.sarif}) so each caller writes a distinct artifact and never overwrites
	 * another's: {@code ""} for the normal source/sink query, {@code "-explore"} for forward
	 * exploration, {@code "-explore-bwd"} for backward exploration.
	 */
	private boolean runNativeQuery(Program program, PluginTool tool, File queryFile,
			String outputTag) throws Exception {
		taintOptions = plugin.getOptions();
		File engineFile = Path.of(taintOptions.getTaintEnginePath()).toFile();
		if (!engineFile.exists()) {
			plugin.consoleMessage("The " + getName() + " binary (" +
				engineFile.getCanonicalPath() + ") cannot be found; set Taint.Directories.Engine.");
			return false;
		}

		String outputDir = taintOptions.getTaintOutputDirectory();
		String store = taintOptions.getTaintStoreDirectory();
		String prog = NativeCtadlRunner.sanitizeName(program.getName());

		// Pre-flight: a query needs an on-disk index for this program. If it is missing, offer
		// to build it now instead of failing later with an opaque "No SARIF generated" error.
		if (!isIndexed(store, prog)) {
			int choice = OptionDialog.showYesNoDialog(tool.getActiveWindow(),
				"Program not indexed",
				"'" + program.getName() + "' has not been indexed yet, so there is nothing to " +
					"query.\n\nRun 'Initialize Program Index' now, then continue the query?");
			if (choice != OptionDialog.YES_OPTION) {
				plugin.consoleMessage(
					"Query skipped: '" + program.getName() + "' is not indexed.");
				return false;
			}
			try {
				// Reuse the full index flow (facts import + index, propagation models, freshness).
				new CreateTargetIndexTask(plugin, program).run(monitor);
			}
			catch (CancelledException e) {
				plugin.consoleMessage("Indexing cancelled; query skipped.");
				return false;
			}
			if (!isIndexed(store, prog)) {
				plugin.consoleMessage("Indexing did not complete; query skipped. " +
					"Check the engine, facts, and store settings.");
				return false;
			}
		}

		File outSarif = Path.of(outputDir, prog + outputTag + ".sarif").toFile();
		plugin.consoleMessage("Using " + getName() + " binary: " + engineFile);

		boolean ok = NativeCtadlRunner.query(engineFile.toString(), store, prog,
			queryFile.getAbsolutePath(), outSarif.getAbsolutePath(),
			msg -> plugin.consoleMessage(msg));
		if (!ok) {
			plugin.consoleMessage(getName() + " query did not complete successfully.");
			return false;
		}

		try (FileInputStream fis = new FileInputStream(outSarif)) {
			readQueryResultsIntoDataFrame(program, fis);
		}
		return true;
	}

	/**
	 * True if the ctadl store already holds an index for {@code prog}. The native pipeline keys the
	 * index by the sanitized program name at {@code <storeRoot>/projects/<prog>/index}.
	 */
	private static boolean isIndexed(String storeOpt, String prog) {
		File indexDir = Path.of(storeRoot(storeOpt), "projects", prog, "index").toFile();
		String[] contents = indexDir.list();
		return contents != null && contents.length > 0;
	}

	/**
	 * The ctadl store root — the directory that directly contains {@code projects/}. When the
	 * {@code Taint.Directories.Store} option is set it is that directory verbatim (the runner passes
	 * it to ctadl via {@code --store}, which is used as the store root with no {@code ctadl}
	 * subdirectory appended). When blank, ctadl's default applies: {@code $XDG_STATE_HOME/ctadl}, or
	 * {@code ~/.local/state/ctadl} when {@code XDG_STATE_HOME} is unset.
	 */
	private static String storeRoot(String storeOpt) {
		if (storeOpt != null && !storeOpt.isBlank()) {
			return storeOpt;
		}
		String xdg = System.getenv("XDG_STATE_HOME");
		String stateHome = (xdg != null && !xdg.isBlank())
				? xdg
				: System.getProperty("user.home") + File.separator + ".local" + File.separator +
					"state";
		return stateHome + File.separator + "ctadl";
	}

	// buildQuery/buildIndex below are superseded by the native driver (queryIndex above
	// and CreateTargetIndexTask's native import+index) and are retained only to satisfy
	// the AbstractTaintState contract; they are no longer invoked.
	@Override
	public void buildQuery(List<String> paramList, String enginePath, File indexDBFile,
			String indexDirectory) {
		paramList.add(enginePath);
		paramList.add("--directory");
		paramList.add(indexDirectory);
		paramList.add("query");
		Comparable<TaintDirection> direction = taintOptions.getTaintDirection();
		if (!direction.equals(TaintDirection.DEFAULT)) {
			paramList.add("--compute-slices");
			switch (taintOptions.getTaintDirection()) {
				case TaintDirection.BOTH -> paramList.add("all");
				case TaintDirection.FORWARD -> paramList.add("fwd");
				case TaintDirection.BACKWARD -> paramList.add("bwd");
				default -> {
					// No action
				}
			}
		}
		paramList.add("--no-compile-analysis");
		paramList.add("-j8");
		paramList.add("--format=" + taintOptions.getTaintOutputForm().toString());
	}

	@Override
	public void buildIndex(List<String> paramList, String enginePath, String factsPath,
			String indexDirectory) {
		paramList.add(enginePath);
		paramList.add("--directory");
		paramList.add(indexDirectory);
		paramList.add("index");
		paramList.add("-j8");
		paramList.add("-f");
		paramList.add(factsPath);
	}

	@Override
	public GhidraScript getExportScript(ConsoleService console, boolean perFunction) {
		String scriptName = getScriptName(perFunction);
		BundleHost bundleHost = GhidraScriptUtil.acquireBundleHostReference();
		for (ResourceFile dir : bundleHost.getBundleFiles()) {
			if (dir.isDirectory()) {
				ResourceFile scriptFile = new ResourceFile(dir, scriptName);
				if (scriptFile.exists()) {
					GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptFile);
					try {
						return provider.getScriptInstance(scriptFile, console.getStdErr());
					}
					catch (GhidraScriptLoadException e) {
						console.addErrorMessage("", "Unable to load script: " + scriptName);
						console.addErrorMessage("", "  detail: " + e.getMessage());
					}
				}
			}
		}
		throw new IllegalArgumentException("Script does not exist: " + scriptName);
	}

	protected String getScriptName(boolean perFunction) {
		return perFunction ? "ExportPCodeForSingleFunction.java" : "ExportPCodeForCTADL.java";
	}

	/**
	 * Writes the query as a single JSON5 "model generator" document, the format
	 * the rust/Ascent CTADL engine consumes (see
	 * {@code ctadl-ascent/src/models/ctadl-model-generator.schema.json}).
	 *
	 * <p>Each active source/sink mark becomes one model generator:
	 * <ul>
	 * <li>A function-name token &rarr; a {@code find: "methods"} generator that
	 * taints the function's {@code Return} port.</li>
	 * <li>Any other token (a variable at a program point) &rarr; a
	 * {@code find: "instructions"} generator pinned, via an {@code address}
	 * constraint, to the instruction the mark sits on. The engine seeds the
	 * interior vertex/vertices defined or used there.</li>
	 * </ul>
	 *
	 * Sanitizer/gate marks have no equivalent in the model format yet and are
	 * skipped with a console note.
	 */
	@Override
	public boolean writeQueryFile(File queryTextFile) throws Exception {
		JsonArray generators = new JsonArray();

		// Sources: active marks + enabled authored source models.
		appendSourceGenerators(generators);

		// Sinks: active marks + enabled authored sink models.
		appendSinkGenerators(generators);

		for (TaintLabel mark : gates) {
			if (mark.isActive()) {
				plugin.consoleMessage(
					"CTADL: sanitizer/gate marks are not supported by the JSON5 model " +
						"format; skipping " + mark);
			}
		}

		writeGenerators(generators, queryTextFile);
		return true;
	}

	/**
	 * Writes the forward-<b>exploration</b> query: the enabled source generators plus one synthetic
	 * catch-all sink (every function with code, sinks on {@code Argument(0..N)}) per distinct source
	 * kind. Making the whole program a sink turns the engine's backward cone into "everything," so
	 * the meet-in-the-middle materializes the source's full forward cone (reported as {@code C0002}
	 * tainted-instructions). Authored/interior sinks and propagation models are intentionally
	 * omitted. Returns false when there is no enabled source to explore (nothing written).
	 */
	public boolean writeExplorationQueryFile(File queryTextFile) throws Exception {
		Set<String> kinds = enabledSourceKinds();
		if (kinds.isEmpty()) {
			return false;
		}
		JsonArray generators = new JsonArray();
		appendSourceGenerators(generators);
		generators.add(catchAllSinkGenerator(kinds));
		writeGenerators(generators, queryTextFile);
		return true;
	}

	/**
	 * Writes the backward-<b>exploration</b> query: the enabled sink generators plus one synthetic
	 * catch-all source (every function with code, sources on {@code Return} and {@code Argument(0..N)})
	 * per distinct sink kind. Making the whole program a source turns the engine's forward cone into
	 * "everything," so the meet-in-the-middle materializes the sink's full backward cone (reported as
	 * {@code C0002} tainted-instructions). Authored/interior sources and propagation models are
	 * intentionally omitted. Returns false when there is no enabled sink to explore (nothing written).
	 */
	public boolean writeBackwardExplorationQueryFile(File queryTextFile) throws Exception {
		Set<String> kinds = enabledSinkKinds();
		if (kinds.isEmpty()) {
			return false;
		}
		JsonArray generators = new JsonArray();
		appendSinkGenerators(generators);
		generators.add(catchAllSourceGenerator(kinds));
		writeGenerators(generators, queryTextFile);
		return true;
	}

	/**
	 * Appends the enabled source generators — active source marks and enabled authored
	 * {@link TaintModel.Role#SOURCE} models — to {@code generators}. Shared by the normal
	 * source/sink query ({@link #writeQueryFile}) and forward exploration
	 * ({@link #writeExplorationQueryFile}).
	 */
	private void appendSourceGenerators(JsonArray generators) {
		for (TaintLabel mark : sources) {
			if (mark.isActive()) {
				JsonObject gen = buildGenerator(mark, true);
				if (gen != null) {
					generators.add(gen);
				}
			}
		}
		for (TaintModel m : authoredModels) {
			if (m.enabled() && m.role() == TaintModel.Role.SOURCE) {
				JsonObject gen = taintModelToGenerator(m);
				if (gen != null) {
					generators.add(gen);
				}
			}
		}
	}

	/**
	 * Appends the enabled sink generators — active sink marks and enabled authored
	 * {@link TaintModel.Role#SINK} models — to {@code generators}. Shared by the normal
	 * source/sink query ({@link #writeQueryFile}) and backward exploration
	 * ({@link #writeBackwardExplorationQueryFile}).
	 */
	private void appendSinkGenerators(JsonArray generators) {
		for (TaintLabel mark : sinks) {
			if (mark.isActive()) {
				JsonObject gen = buildGenerator(mark, false);
				if (gen != null) {
					generators.add(gen);
				}
			}
		}
		for (TaintModel m : authoredModels) {
			if (m.enabled() && m.role() == TaintModel.Role.SINK) {
				JsonObject gen = taintModelToGenerator(m);
				if (gen != null) {
					generators.add(gen);
				}
			}
		}
	}

	/** Serializes {@code generators} as the engine's {@code {model_generators:[...]}} document. */
	private void writeGenerators(JsonArray generators, File queryTextFile) throws Exception {
		JsonObject root = new JsonObject();
		root.add("model_generators", generators);

		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		try (PrintWriter writer = new PrintWriter(queryTextFile)) {
			writer.println(gson.toJson(root));
		}
		plugin.consoleMessage("Wrote Query File: " + queryTextFile);
	}

	/**
	 * Builds a single model generator for a source or sink mark. Returns null if
	 * the mark cannot be expressed (e.g. no enclosing function).
	 */
	private JsonObject buildGenerator(TaintLabel mark, boolean isSource) {
		String function = mark.getFunctionName();
		if (function == null) {
			return null;
		}

		JsonArray where = new JsonArray();
		JsonObject sigMatch = new JsonObject();
		sigMatch.addProperty("constraint", "signature_match");
		sigMatch.addProperty("name", function);
		where.add(sigMatch);

		// The taint label (kind) the user assigned to this mark.
		JsonObject endpoint = new JsonObject();
		endpoint.addProperty("kind", mark.getLabel());

		JsonObject generator = new JsonObject();
		ClangToken token = mark.getToken();
		if (token instanceof ClangFuncNameToken) {
			// Function-level: taint the function's return value.
			generator.addProperty("find", "methods");
			endpoint.addProperty("port", "Return");
		}
		else {
			// Interior vertex: pin to the instruction address of the marked token.
			generator.addProperty("find", "instructions");
			Address addr = mark.getAddress();
			long offset = addr != null ? addr.getOffset() : 0L;
			JsonObject addrConstraint = new JsonObject();
			addrConstraint.addProperty("constraint", "address");
			addrConstraint.addProperty("value", "0x" + Long.toHexString(offset));
			where.add(addrConstraint);
			// Interior-vertex endpoints carry no port.
		}

		JsonArray endpoints = new JsonArray();
		endpoints.add(endpoint);
		JsonObject model = new JsonObject();
		model.add(isSource ? "sources" : "sinks", endpoints);

		generator.add("where", where);
		generator.add("model", model);
		return generator;
	}

	/**
	 * Converts a picker-authored source/sink {@link TaintModel} into a {@code find:"methods"}
	 * model generator. Propagation models return null (they are index-time, not query-time).
	 */
	private JsonObject taintModelToGenerator(TaintModel m) {
		if (m.role() == TaintModel.Role.PROPAGATION) {
			return null;
		}
		JsonArray names = new JsonArray();
		for (String fn : m.functionNames()) {
			names.add(fn);
		}
		JsonObject sig = new JsonObject();
		sig.addProperty("constraint", "signature_match");
		sig.add("names", names);
		JsonArray where = new JsonArray();
		where.add(sig);

		JsonObject endpoint = new JsonObject();
		endpoint.addProperty("port", m.port());
		endpoint.addProperty("kind", m.kind());
		JsonArray endpoints = new JsonArray();
		endpoints.add(endpoint);
		JsonObject model = new JsonObject();
		model.add(m.role() == TaintModel.Role.SOURCE ? "sources" : "sinks", endpoints);

		JsonObject gen = new JsonObject();
		gen.addProperty("find", "methods");
		gen.add("where", where);
		gen.add("model", model);
		return gen;
	}

	/**
	 * Argument ports {@code 0..EXPLORE_MAX_ARG} used for the exploration catch-all sink. The engine
	 * has no argument wildcard, so the range is enumerated with a generous fixed bound. Consequence:
	 * a forward cone that flows <em>only</em> into argument &gt; {@code EXPLORE_MAX_ARG} of some
	 * function is not captured — exploration is a plugin-side approximation of a forward slice, not a
	 * complete one (see the Denis findings doc). Functions with &le; 16 parameters (the common case)
	 * are fully covered.
	 */
	private static final int EXPLORE_MAX_ARG = 15;

	/**
	 * The distinct taint kinds of the currently enabled sources (active source marks + enabled
	 * authored source models). Used to pair the exploration catch-all sink with the right kind(s);
	 * order-preserving so the emitted model is stable.
	 */
	private Set<String> enabledSourceKinds() {
		Set<String> kinds = new LinkedHashSet<>();
		for (TaintLabel mark : sources) {
			// A null-label mark would still be emitted as a source by buildGenerator (with a null
			// kind), but it gets no matching catch-all sink kind here, so it contributes no forward
			// cone. Marks normally always carry a label, so this only skips a degenerate source.
			if (mark.isActive() && mark.getLabel() != null) {
				kinds.add(mark.getLabel());
			}
		}
		for (TaintModel m : authoredModels) {
			if (m.enabled() && m.role() == TaintModel.Role.SOURCE && m.kind() != null) {
				kinds.add(m.kind());
			}
		}
		return kinds;
	}

	/** True if there is an active source mark or enabled authored source model to explore. */
	public boolean hasEnabledSource() {
		return !enabledSourceKinds().isEmpty();
	}

	/**
	 * The distinct taint kinds of the currently enabled sinks (active sink marks + enabled authored
	 * sink models). Used to pair the backward-exploration catch-all source with the right kind(s);
	 * order-preserving so the emitted model is stable.
	 */
	private Set<String> enabledSinkKinds() {
		Set<String> kinds = new LinkedHashSet<>();
		for (TaintLabel mark : sinks) {
			// Mirror of enabledSourceKinds: a null-label mark would still be emitted as a sink by
			// buildGenerator (with a null kind), but it gets no matching catch-all source kind here,
			// so it contributes no backward cone. Marks normally always carry a label.
			if (mark.isActive() && mark.getLabel() != null) {
				kinds.add(mark.getLabel());
			}
		}
		for (TaintModel m : authoredModels) {
			if (m.enabled() && m.role() == TaintModel.Role.SINK && m.kind() != null) {
				kinds.add(m.kind());
			}
		}
		return kinds;
	}

	/** True if there is an active sink mark or enabled authored sink model to explore. */
	public boolean hasEnabledSink() {
		return !enabledSinkKinds().isEmpty();
	}

	/**
	 * Builds the synthetic catch-all sink generator for forward exploration: every function with a
	 * body ({@code has_code}) is a sink on {@code Argument(0..EXPLORE_MAX_ARG)}, one endpoint per
	 * distinct source {@code kind}. This makes the engine's backward cone cover the whole program so
	 * the source's forward cone is fully materialized. (An engine-native forward slice would replace
	 * this; {@code --compute-slices} is currently a no-op — see the Denis findings doc.)
	 */
	private JsonObject catchAllSinkGenerator(Set<String> kinds) {
		JsonArray where = new JsonArray();
		JsonObject hasCode = new JsonObject();
		hasCode.addProperty("constraint", "has_code");
		where.add(hasCode);

		JsonArray sinks = new JsonArray();
		for (String kind : kinds) {
			for (int i = 0; i <= EXPLORE_MAX_ARG; i++) {
				JsonObject ep = new JsonObject();
				ep.addProperty("port", "Argument(" + i + ")");
				ep.addProperty("kind", kind);
				sinks.add(ep);
			}
		}
		JsonObject model = new JsonObject();
		model.add("sinks", sinks);

		JsonObject gen = new JsonObject();
		gen.addProperty("find", "methods");
		gen.add("where", where);
		gen.add("model", model);
		return gen;
	}

	/**
	 * Builds the synthetic catch-all source generator for backward exploration: every function with a
	 * body ({@code has_code}) is a source on {@code Return} and {@code Argument(0..EXPLORE_MAX_ARG)},
	 * one endpoint per distinct sink {@code kind}. This makes the engine's forward cone cover the whole
	 * program so the sink's backward cone is fully materialized. (An engine-native backward slice would
	 * replace this; {@code --compute-slices} is currently a no-op — see the Denis findings doc.)
	 */
	private JsonObject catchAllSourceGenerator(Set<String> kinds) {
		JsonArray where = new JsonArray();
		JsonObject hasCode = new JsonObject();
		hasCode.addProperty("constraint", "has_code");
		where.add(hasCode);

		JsonArray sources = new JsonArray();
		for (String kind : kinds) {
			JsonObject ret = new JsonObject();
			ret.addProperty("port", "Return");
			ret.addProperty("kind", kind);
			sources.add(ret);
			for (int i = 0; i <= EXPLORE_MAX_ARG; i++) {
				JsonObject ep = new JsonObject();
				ep.addProperty("port", "Argument(" + i + ")");
				ep.addProperty("kind", kind);
				sources.add(ep);
			}
		}
		JsonObject model = new JsonObject();
		model.add("sources", sources);

		JsonObject gen = new JsonObject();
		gen.addProperty("find", "methods");
		gen.add("where", where);
		gen.add("model", model);
		return gen;
	}

	/** Adds picker-authored models (see {@link TaintModelDialog}) to this state's model set. */
	public void addModels(List<TaintModel> models) {
		authoredModels.addAll(models);
		// A newly added propagation model invalidates the current index.
		for (TaintModel m : models) {
			indexFreshness.onModelChanged(m);
		}
	}

	/** The picker-authored models currently held by this state. */
	public List<TaintModel> getAuthoredModels() {
		return authoredModels;
	}

	/**
	 * Index freshness tracker for propagation (index-time) models. Callers mark it stale via
	 * {@link IndexFreshness#onModelChanged} on a model edit and {@link IndexFreshness#markIndexed}
	 * after a successful re-index.
	 */
	public IndexFreshness getIndexFreshness() {
		return indexFreshness;
	}

	// The parent's per-mark line hooks are unused: writeQueryFile above emits a
	// single structured JSON document instead of appending Datalog lines.
	@Override
	protected void writeHeader(PrintWriter writer) {
		// unused (see writeQueryFile)
	}

	@Override
	protected void writeRule(PrintWriter writer, TaintLabel mark, boolean isSource) {
		// unused (see writeQueryFile)
	}

	@Override
	public void writeGate(PrintWriter writer, TaintLabel mark) {
		// unused (see writeQueryFile)
	}

	@Override
	protected void writeFooter(PrintWriter writer) {
		// unused (see writeQueryFile)
	}

}
