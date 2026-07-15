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
package ghidra.app.plugin.core.decompiler.taint.actions;

import docking.action.MenuData;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompiler.taint.TaintPlugin;
import ghidra.app.plugin.core.decompiler.taint.TaintPlugin.TaintFormat;
import ghidra.app.plugin.core.decompiler.taint.TaintState;
import ghidra.app.plugin.core.decompiler.taint.ctadl.CTADLTaintState;
import ghidra.app.plugin.core.decompiler.taint.sarif.SarifTaintGraphRunHandler;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import sarif.SarifService;

/**
 * Runs a <b>forward taint exploration</b> from the currently enabled source(s): the ctadl engine is
 * meet-in-the-middle, so a source with no sink materializes nothing. This action pairs the enabled
 * sources with a synthetic catch-all sink (see
 * {@link CTADLTaintState#queryForwardExploration}) so the source's full forward cone is computed and
 * highlighted. Results surface as {@code C0002} tainted-instructions — apply the "All tainted"
 * highlight scope to see them.
 *
 * <p>Only available with the ctadl engine and only when at least one source is enabled (author one
 * via <em>Model function ports…</em> or a source mark first).
 */
public class TaintExploreFromSourceAction extends TaintAbstractDecompilerAction {

	private final TaintPlugin plugin;

	public TaintExploreFromSourceAction(TaintPlugin plugin) {
		super("Explore Taint From Source");
		setHelpLocation(new HelpLocation(TaintPlugin.HELP_LOCATION, "TaintExploreFromSource"));
		setPopupMenuData(
			new MenuData(new String[] { "Taint", "Explore taint from source…" }, "Decompile"));
		this.plugin = plugin;
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		return plugin.getTaintState() instanceof CTADLTaintState state && state.hasEnabledSource();
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		Program program = context.getProgram();
		PluginTool tool = context.getTool();

		Task task = new Task("Forward taint exploration", true, true, true, true) {
			@Override
			public void run(TaskMonitor monitor) {
				TaintState state = plugin.getTaintState();
				state.setMonitor(monitor);
				((CTADLTaintState) state).queryForwardExploration(program, tool);
				state.setMonitor(null);
			}
		};

		// Blocking (like the source/sink query) so the table/highlight work happens off the task
		// thread; the user still gets a progress bar + cancel.
		tool.execute(task);

		if (task.isCancelled()) {
			plugin.consoleMessage("Forward taint exploration was cancelled.");
			return;
		}

		TaintState state = plugin.getTaintState();
		TaintFormat format = state.getOptions().getTaintOutputForm();
		if (!format.equals(TaintFormat.NONE)) {
			SarifService sarifService = plugin.getSarifService();
			sarifService.getController().setDefaultGraphHander(SarifTaintGraphRunHandler.class);
			String queryName = state.getQueryName();
			sarifService.showSarif(queryName != null ? queryName : "explore", state.getData());
		}
		plugin.getProvider().setTaint();
		plugin.consoleMessage("exploration query complete");
	}
}
