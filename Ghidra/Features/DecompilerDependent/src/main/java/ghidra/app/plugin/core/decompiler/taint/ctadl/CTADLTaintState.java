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
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import docking.widgets.filechooser.GhidraFileChooser;
import generic.jar.ResourceFile;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.decompiler.taint.*;
import ghidra.app.plugin.core.decompiler.taint.TaintPlugin.TaintDirection;
import ghidra.app.plugin.core.osgi.BundleHost;
import ghidra.app.script.*;
import ghidra.app.plugin.core.decompiler.taint.ctadl.model.TaintModel;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

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
			File engineFile = Path.of(taintOptions.getTaintEnginePath()).toFile();
			if (!engineFile.exists()) {
				plugin.consoleMessage("The " + getName() + " binary (" +
					engineFile.getCanonicalPath() + ") cannot be found; set Taint.Directories.Engine.");
				return false;
			}

			String outputDir = taintOptions.getTaintOutputDirectory();
			String store = taintOptions.getTaintStoreDirectory();
			String prog = NativeCtadlRunner.sanitizeName(program.getName());

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

			File outSarif = Path.of(outputDir, prog + ".sarif").toFile();
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
		catch (Exception e) {
			Msg.error(this, "Problems running query: " + e);
			return false;
		}
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

		for (TaintLabel mark : sources) {
			if (mark.isActive()) {
				JsonObject gen = buildGenerator(mark, true);
				if (gen != null) {
					generators.add(gen);
				}
			}
		}

		for (TaintLabel mark : sinks) {
			if (mark.isActive()) {
				JsonObject gen = buildGenerator(mark, false);
				if (gen != null) {
					generators.add(gen);
				}
			}
		}

		for (TaintLabel mark : gates) {
			if (mark.isActive()) {
				plugin.consoleMessage(
					"CTADL: sanitizer/gate marks are not supported by the JSON5 model " +
						"format; skipping " + mark);
			}
		}

		// Function-centric models authored via the picker (source/sink only; propagation
		// models are index-time and are applied during Create Index, not here). Only
		// enabled models (see the Taint Models panel) contribute to the query.
		for (TaintModel m : authoredModels) {
			if (!m.enabled()) {
				continue;
			}
			JsonObject gen = taintModelToGenerator(m);
			if (gen != null) {
				generators.add(gen);
			}
		}

		JsonObject root = new JsonObject();
		root.add("model_generators", generators);

		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		try (PrintWriter writer = new PrintWriter(queryTextFile)) {
			writer.println(gson.toJson(root));
		}

		plugin.consoleMessage("Wrote Query File: " + queryTextFile);
		return true;
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

	/** Adds picker-authored models (see {@link TaintModelDialog}) to this state's model set. */
	public void addModels(List<TaintModel> models) {
		authoredModels.addAll(models);
	}

	/** The picker-authored models currently held by this state. */
	public List<TaintModel> getAuthoredModels() {
		return authoredModels;
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
