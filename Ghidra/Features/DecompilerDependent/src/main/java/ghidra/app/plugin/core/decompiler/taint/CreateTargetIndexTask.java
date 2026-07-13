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
package ghidra.app.plugin.core.decompiler.taint;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.plugin.core.decompiler.taint.ctadl.CTADLTaintState;
import ghidra.app.plugin.core.decompiler.taint.ctadl.NativeCtadlRunner;
import ghidra.app.plugin.core.decompiler.taint.ctadl.model.ModelJsonlWriter;
import ghidra.app.plugin.core.decompiler.taint.ctadl.model.TaintModel;
import ghidra.app.services.ConsoleService;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class CreateTargetIndexTask extends Task {

	private TaintPlugin plugin;
	private Program program;

	public CreateTargetIndexTask(TaintPlugin plugin, Program program) {
		super("Create Target Index Action", true, true, false, false);
		this.plugin = plugin;
		this.program = program;
	}

	private File getFilePath(String initial_directory, String title) {

		GhidraFileChooser chooser = new GhidraFileChooser(null);
		chooser.setCurrentDirectory(new File(initial_directory));
		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		chooser.setTitle(title);
		File selectedFile = chooser.getSelectedFile();
		if (selectedFile != null) {
			return selectedFile;
		}

		return selectedFile;
	}

	private String getDirectoryPath(String path, String title) {

		GhidraFileChooser chooser = new GhidraFileChooser(null);
		chooser.setCurrentDirectory(new File(path));
		chooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
		chooser.setTitle(title);
		File selectedDir = chooser.getCurrentDirectory();
		if (selectedDir != null && !chooser.wasCancelled()) {
			return selectedDir.getAbsolutePath();
		}
		return null;
	}

	private boolean indexProgram(String engine_path, String facts_path, String index_directory) {
		// Native ctadl: import the exported facts directory (Ghidra is skipped via the
		// facts-dir short-circuit) then index it, keyed by the sanitized program name,
		// into the store selected by Taint.Directories.Store (empty = ctadl default).
		// index_directory is unused under the native store model.
		String store = plugin.getOptions().getTaintStoreDirectory();
		String prog = NativeCtadlRunner.sanitizeName(program.getName());
		CTADLTaintState state = plugin.getTaintState() instanceof CTADLTaintState c ? c : null;

		// Propagation (index-time) models authored via the picker are applied here via `-m`.
		// Only enabled propagation models are emitted; none => null (no `-m` flag).
		String propagationFile = writePropagationFile(state);

		boolean success = NativeCtadlRunner.importAndIndex(engine_path, store, prog, facts_path,
			propagationFile, msg -> plugin.consoleMessage(msg));

		if (success && state != null) {
			// The on-disk index now reflects the current propagation models.
			state.getIndexFreshness().markIndexed();
			plugin.refreshTaintModelsPanel();
		}
		return success;
	}

	/**
	 * Writes the enabled propagation models to a temp JSONL for {@code ctadl index -m}. Returns
	 * the file path, or null when there are no enabled propagation models (so no `-m` flag).
	 */
	private String writePropagationFile(CTADLTaintState state) {
		if (state == null) {
			return null;
		}
		List<TaintModel> models = state.getAuthoredModels();
		String jsonl = ModelJsonlWriter.toJsonl(models, TaintModel.Destination.INDEX);
		if (jsonl.isBlank()) {
			return null;
		}
		try {
			File f = File.createTempFile("ctadl-propagation", ".jsonl");
			f.deleteOnExit();
			Files.writeString(f.toPath(), jsonl);
			plugin.consoleMessage("Wrote propagation model file (" + jsonl.lines().count() +
				" model(s)): " + f.getAbsolutePath());
			return f.getAbsolutePath();
		}
		catch (IOException e) {
			plugin.consoleMessage("Failed to write propagation model file: " + e +
				" (indexing without propagation models)");
			return null;
		}
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {

		monitor.initialize(program.getFunctionManager().getFunctionCount());
		PluginTool tool = plugin.getTool();
		ConsoleService consoleService = tool.getService(ConsoleService.class);

		ToolOptions options = tool.getOptions("Decompiler");

		// This will pull all the Taint options default set in the plugin.  These could also be set in Ghidra configuration files.
		String enginePathName = options.getString(TaintOptions.OP_KEY_TAINT_ENGINE_PATH,
			"/home/user/workspace/engine_binary").trim();
		String factsDirectory =
			options.getString(TaintOptions.OP_KEY_TAINT_FACTS_DIR, "/tmp/export").trim();
		String indexDirectory =
			options.getString(TaintOptions.OP_KEY_TAINT_OUTPUT_DIR, "/tmp/output").trim();
		String indexDBName = options.getString(TaintOptions.OP_KEY_TAINT_DB, "ctadlir.db").trim();

		// builds a custom db name with the string of the binary embedded in it for better identification.
		indexDBName = TaintOptions.makeDBName(indexDBName, program.getName());

		Path enginePath = Path.of(enginePathName);
		File engineFile = enginePath.toFile();

		if (!engineFile.exists() || !engineFile.canExecute()) {
			Msg.info(this, "The engine binary (" + engineFile.toString() +
				") cannot be found or executed.");
			engineFile = getFilePath(enginePathName, "Select the engine binary");
		}

		consoleService.addMessage("Create Index", "using engine at: " + engineFile.toString());

		Path factsPath = Path.of(factsDirectory);

		if (!factsPath.toFile().exists() || !factsPath.toFile().isDirectory()) {
			Msg.info(this, "Facts Path: " + factsPath.toString() + " does not exist.");
			factsDirectory = getDirectoryPath(factsDirectory,
				"Select full path to the directory containing the FACTS files");
			if (factsDirectory == null) {
				Msg.info(this, "User cancelled operation; existing script.");
				return;
			}
			Msg.info(this, "Using .facts files in: " + factsDirectory);
			options.setString(TaintOptions.OP_KEY_TAINT_FACTS_DIR, factsDirectory);
		}
		else {
			factsDirectory = factsPath.toString();
		}

		consoleService.addMessage("Create Index", "using facts path: " + factsDirectory);
		Path indexPath0 = Path.of(indexDirectory);
		Path indexPath = Path.of(indexDirectory, indexDBName);

		if (!indexPath0.toFile().exists() || !indexPath0.toFile().isDirectory()) {
			// the index has already been build. Use it?
			Msg.info(this, "Index Path: " + indexPath.toString() + " does not exist.");
			indexDirectory = getDirectoryPath(indexDirectory,
				"Select full path to the directory to containthe INDEX file");
			indexPath = Path.of(indexDirectory, indexDBName);
			options.setString(TaintOptions.OP_KEY_TAINT_OUTPUT_DIR, indexDirectory);
		}

		consoleService.addMessage("Create Index", "using index path: " + indexDirectory);
		Msg.info(this, "Engine Path: " + engineFile.toString());
		Msg.info(this, "Facts Path: " + factsDirectory);
		Msg.info(this, "Index Path: " + indexDirectory);

		boolean success = indexProgram(engineFile.toString(), factsDirectory, indexDirectory);
		consoleService.addMessage("Create Index", "indexing status: " + success);
		monitor.clearCancelled();
	}
}
