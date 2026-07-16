/* ###
 * IP: GHIDRA
 */
package ghidra.app.plugin.core.decompiler.taint.ctadl;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.table.GTable;
import ghidra.app.plugin.core.decompiler.taint.TaintPlugin;
import ghidra.app.plugin.core.decompiler.taint.TaintPlugin.TaintFormat;
import ghidra.app.plugin.core.decompiler.taint.TaintState;
import ghidra.app.plugin.core.decompiler.taint.ctadl.model.TaintModel;
import ghidra.app.plugin.core.decompiler.taint.sarif.SarifTaintGraphRunHandler;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import resources.Icons;
import sarif.SarifService;

/**
 * Dockable manager for the function-centric taint models authored via {@link TaintModelDialog}.
 * Lists each model (enabled · function · role · port(s) · kind), lets the analyst toggle a model
 * on/off (only enabled models feed the query), delete it, or double-click a row to edit that
 * function's models in the picker (pre-filled). Backed by the live authored-models list in
 * {@link CTADLTaintState}.
 *
 * <p>Propagation models are index-time: toggling one warns that a re-index is required, and a
 * banner reflects the {@link ghidra.app.plugin.core.decompiler.taint.ctadl.model.IndexFreshness}
 * state so the analyst sees when the on-disk index no longer matches the propagation models.
 */
public class TaintModelPanel extends ComponentProviderAdapter {

	private final TaintPlugin plugin;
	private final JComponent mainPanel;
	private final JLabel staleBanner;
	private final ModelTableModel tableModel;
	private final GTable table;

	public TaintModelPanel(TaintPlugin plugin) {
		super(plugin.getTool(), "Taint Models", plugin.getName());
		this.plugin = plugin;
		setTitle("Taint Models");

		tableModel = new ModelTableModel();
		table = new GTable(tableModel);
		table.getColumnModel().getColumn(0).setMaxWidth(60); // Enabled checkbox

		// Double-click a row (outside the Enabled checkbox) to edit the function's models in the
		// picker, pre-filled with its current models.
		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() != 2 || !SwingUtilities.isLeftMouseButton(e)) {
					return;
				}
				int row = table.rowAtPoint(e.getPoint());
				int col = table.columnAtPoint(e.getPoint());
				if (row >= 0 && col != 0) {
					editRow(row);
				}
			}
		});

		staleBanner = new JLabel();
		staleBanner.setForeground(Color.RED.darker());
		staleBanner.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));
		staleBanner.setVisible(false);

		mainPanel = new JPanel(new BorderLayout());
		mainPanel.add(staleBanner, BorderLayout.NORTH);
		mainPanel.add(new JScrollPane(table), BorderLayout.CENTER);

		createActions();
	}

	private void createActions() {
		DockingAction delete = new DockingAction("Delete Taint Model", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				int row = table.getSelectedRow();
				List<TaintModel> models = currentModels();
				if (row >= 0 && row < models.size()) {
					TaintModel removed = models.remove(row);
					// Deleting a propagation model invalidates the index (banner only, no modal).
					CTADLTaintState state = currentState();
					if (state != null) {
						state.getIndexFreshness().onModelChanged(removed);
					}
					refresh();
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return table.getSelectedRow() >= 0;
			}
		};
		delete.setToolBarData(new ToolBarData(Icons.DELETE_ICON));
		delete.setPopupMenuData(new MenuData(new String[] { "Delete model" }));
		addLocalAction(delete);

		// Forward taint exploration: runs the enabled source model(s) against a synthetic
		// catch-all sink so the source's forward cone is highlighted. It operates on the whole
		// enabled-model set (not a decompiler cursor position), so it belongs on this panel's
		// toolbar rather than the context menu.
		DockingAction explore = new DockingAction("Explore Forward Taint", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				runExploration();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				CTADLTaintState state = currentState();
				return state != null && state.hasEnabledSource();
			}
		};
		explore.setToolBarData(new ToolBarData(Icons.ARROW_DOWN_RIGHT_ICON));
		explore.setPopupMenuData(new MenuData(new String[] { "Explore forward taint" }));
		explore.setDescription("Run a forward taint exploration from the enabled source model(s): " +
			"pairs them with a catch-all sink so the source's forward cone is computed. Apply the " +
			"'All tainted' highlight scope to see it.");
		addLocalAction(explore);

		// Backward taint exploration: the mirror of forward — runs the enabled sink model(s)
		// against a synthetic catch-all source so the sink's backward cone (everything that can
		// taint it) is highlighted. Also model-set-wide, so it belongs on this toolbar.
		DockingAction exploreBack =
			new DockingAction("Explore Backward Taint", plugin.getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					runBackwardExploration();
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					CTADLTaintState state = currentState();
					return state != null && state.hasEnabledSink();
				}
			};
		exploreBack.setToolBarData(new ToolBarData(Icons.ARROW_UP_LEFT_ICON));
		exploreBack.setPopupMenuData(new MenuData(new String[] { "Explore backward taint" }));
		exploreBack.setDescription(
			"Run a backward taint exploration into the enabled sink model(s): pairs them with a " +
				"catch-all source so the sink's backward cone is computed. Apply the 'All tainted' " +
				"highlight scope to see it.");
		addLocalAction(exploreBack);
	}

	/**
	 * Runs a forward taint exploration from the currently enabled sources and displays the result,
	 * mirroring the query actions' task &rarr; showSarif &rarr; setTaint flow. The exploration query
	 * itself lives in {@link CTADLTaintState#queryForwardExploration}. Unlike the decompiler query
	 * actions this is model-set-wide, not tied to the cursor — hence its home on this panel.
	 */
	private void runExploration() {
		CTADLTaintState state = currentState();
		if (state == null) {
			return;
		}
		Program program = plugin.getCurrentProgram();
		if (program == null) {
			Msg.showWarn(this, null, "No program", "Open a program before exploring taint.");
			return;
		}
		PluginTool tool = plugin.getTool();

		Task task = new Task("Forward taint exploration", true, true, true, true) {
			@Override
			public void run(TaskMonitor monitor) {
				state.setMonitor(monitor);
				state.queryForwardExploration(program, tool);
				state.setMonitor(null);
			}
		};
		tool.execute(task);

		if (task.isCancelled()) {
			plugin.consoleMessage("Forward taint exploration was cancelled.");
			return;
		}
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

	/**
	 * Runs a backward taint exploration into the currently enabled sinks and displays the result,
	 * mirroring {@link #runExploration()}. The exploration query itself lives in
	 * {@link CTADLTaintState#queryBackwardExploration}. Model-set-wide, not tied to the cursor —
	 * hence its home on this panel.
	 */
	private void runBackwardExploration() {
		CTADLTaintState state = currentState();
		if (state == null) {
			return;
		}
		Program program = plugin.getCurrentProgram();
		if (program == null) {
			Msg.showWarn(this, null, "No program", "Open a program before exploring taint.");
			return;
		}
		PluginTool tool = plugin.getTool();

		Task task = new Task("Backward taint exploration", true, true, true, true) {
			@Override
			public void run(TaskMonitor monitor) {
				state.setMonitor(monitor);
				state.queryBackwardExploration(program, tool);
				state.setMonitor(null);
			}
		};
		tool.execute(task);

		if (task.isCancelled()) {
			plugin.consoleMessage("Backward taint exploration was cancelled.");
			return;
		}
		TaintFormat format = state.getOptions().getTaintOutputForm();
		if (!format.equals(TaintFormat.NONE)) {
			SarifService sarifService = plugin.getSarifService();
			sarifService.getController().setDefaultGraphHander(SarifTaintGraphRunHandler.class);
			String queryName = state.getQueryName();
			sarifService.showSarif(queryName != null ? queryName : "explore-bwd", state.getData());
		}
		plugin.getProvider().setTaint();
		plugin.consoleMessage("backward exploration query complete");
	}

	/**
	 * Edit-in-place: reopen the picker for the clicked row's function, seeded with <em>all</em> of
	 * that function's current models (the picker is function-scoped — it authors multiple models
	 * per function at once). On OK, the function's whole model set is replaced with the result.
	 */
	private void editRow(int row) {
		CTADLTaintState state = currentState();
		if (state == null) {
			return;
		}
		List<TaintModel> models = currentModels();
		if (row < 0 || row >= models.size()) {
			return;
		}
		TaintModel clicked = models.get(row);

		Program program = plugin.getCurrentProgram();
		if (program == null) {
			Msg.showWarn(this, null, "Cannot edit model", "Open the program to edit its taint models.");
			return;
		}
		Function func = resolveFunction(program, clicked.functionNames());
		if (func == null) {
			Msg.showWarn(this, null, "Cannot edit model", "Function '" +
				String.join(",", clicked.functionNames()) + "' was not found in the current program.");
			return;
		}

		// The picker is function-scoped, so gather every model for the same function and edit them
		// together. Re-authored models come back enabled (the picker has no enabled toggle).
		List<TaintModel> group = new ArrayList<>();
		for (TaintModel m : models) {
			if (m.functionNames().equals(clicked.functionNames())) {
				group.add(m);
			}
		}

		// This by-name edit path has no decompiler context, so the picker can only show committed
		// formal parameters (no HighFunction fallback). If the function has none but the models
		// reference argument ports, editing them here isn't possible — direct the analyst to commit
		// the signature (the decompiler right-click authoring path uses the inferred signature).
		boolean refsArg = group.stream()
				.anyMatch(m -> isArg(m.port()) || isArg(m.inputPort()) || isArg(m.outputPort()));
		if (func.getParameters().length == 0 && refsArg) {
			Msg.showWarn(this, null, "Commit signature to edit",
				"'" + func.getName() + "' has no committed parameters, so its argument ports " +
					"can't be shown here.\nOpen it in the decompiler and run Commit Params/Return, " +
					"then edit (or re-author it from the decompiler right-click).");
			return;
		}

		TaintModelDialog dialog = new TaintModelDialog(func, group);
		plugin.getTool().showDialog(dialog);
		if (dialog.isCancelled()) {
			return;
		}

		// Replace the function's whole model set with the re-authored result. Removing a
		// propagation model (and adding via addModels) both notify IndexFreshness.
		models.removeAll(group);
		for (TaintModel m : group) {
			state.getIndexFreshness().onModelChanged(m);
		}
		state.addModels(dialog.getResult());
		refresh();
	}

	/** True if a stored port string references an argument (vs. Return / null). */
	private static boolean isArg(String port) {
		return port != null && port.startsWith("Argument");
	}

	/**
	 * Resolve the function named by a model. Checks global (in-memory) functions first — including
	 * PLT thunks — then external/imported functions (e.g. libc {@code recv}), which live outside the
	 * global namespace but are what the model stores (the picker records the thunked target's name).
	 * Returns null if no function matches.
	 */
	private static Function resolveFunction(Program program, List<String> names) {
		if (names.isEmpty()) {
			return null;
		}
		String name = names.get(0);
		List<Function> globals = program.getListing().getGlobalFunctions(name);
		if (!globals.isEmpty()) {
			return globals.get(0);
		}
		for (Function f : program.getFunctionManager().getExternalFunctions()) {
			if (name.equals(f.getName())) {
				return f;
			}
		}
		return null;
	}

	/** The current ctadl state, or null if the active taint engine is not ctadl. */
	private CTADLTaintState currentState() {
		TaintState s = plugin.getTaintState();
		return s instanceof CTADLTaintState c ? c : null;
	}

	/** The live authored-models list from the current ctadl state (empty if not ctadl). */
	private List<TaintModel> currentModels() {
		CTADLTaintState c = currentState();
		return c != null ? c.getAuthoredModels() : List.of();
	}

	/** Refresh the table and stale banner from the backing state; shows the panel if hidden. */
	public void refresh() {
		tableModel.fireTableDataChanged();
		setSubTitle(currentModels().size() + " model(s)");
		CTADLTaintState state = currentState();
		boolean stale = state != null && state.getIndexFreshness().isStale();
		staleBanner.setText(stale
				? "⚠ Index out of date — re-run Initialize Program Index to apply propagation changes"
				: "");
		staleBanner.setVisible(stale);
		// The enabled state of the Explore Forward/Backward toolbar actions depends on the model
		// set (hasEnabledSource/hasEnabledSink), which changes here (add, delete, and the restore-
		// from-persistence flush on tool restart). Kick the tool so those local actions re-evaluate
		// isEnabledForContext — otherwise a restored source/sink leaves the buttons greyed out.
		contextChanged();
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	private class ModelTableModel extends AbstractTableModel {
		private final String[] cols = { "Enabled", "Function", "Role", "Port(s)", "Kind" };

		@Override
		public int getRowCount() {
			return currentModels().size();
		}

		@Override
		public int getColumnCount() {
			return cols.length;
		}

		@Override
		public String getColumnName(int col) {
			return cols[col];
		}

		@Override
		public Class<?> getColumnClass(int col) {
			return col == 0 ? Boolean.class : String.class;
		}

		@Override
		public boolean isCellEditable(int row, int col) {
			return col == 0;
		}

		@Override
		public Object getValueAt(int row, int col) {
			TaintModel m = currentModels().get(row);
			return switch (col) {
				case 0 -> m.enabled();
				case 1 -> String.join(",", m.functionNames());
				case 2 -> m.role().name().toLowerCase();
				case 3 -> m.role() == TaintModel.Role.PROPAGATION
						? disp(m.inputDisplay(), m.inputPort()) + " → " + disp(m.outputDisplay(), m.outputPort())
						: disp(m.portDisplay(), m.port());
				case 4 -> m.role() == TaintModel.Role.PROPAGATION ? "" : m.kind();
				default -> "";
			};
		}

		@Override
		public void setValueAt(Object value, int row, int col) {
			if (col != 0) {
				return;
			}
			TaintModel m = currentModels().get(row);
			m.setEnabled((Boolean) value);
			fireTableCellUpdated(row, col);
			// Toggling a source/sink model's enabled state changes whether the Explore
			// Forward/Backward buttons should be enabled; re-evaluate the panel's local toolbar
			// actions (the propagation branch below also refreshes, which is idempotent here).
			TaintModelPanel.this.contextChanged();
			// Enabling/disabling a propagation model changes the index: mark stale and warn once.
			if (m.role() == TaintModel.Role.PROPAGATION) {
				CTADLTaintState state = currentState();
				if (state != null) {
					state.getIndexFreshness().onModelChanged(m);
				}
				refresh();
				Msg.showWarn(this, null, "Re-index required", CTADLTaintState.REINDEX_WARNING);
			}
		}

		private static String disp(String display, String raw) {
			return display != null ? display : raw;
		}
	}
}
