/* ###
 * IP: GHIDRA
 */
package ghidra.app.plugin.core.decompiler.taint.ctadl;

import java.awt.BorderLayout;
import java.awt.Color;
import java.util.List;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.table.GTable;
import ghidra.app.plugin.core.decompiler.taint.TaintPlugin;
import ghidra.app.plugin.core.decompiler.taint.TaintState;
import ghidra.app.plugin.core.decompiler.taint.ctadl.model.TaintModel;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.util.Msg;
import resources.Icons;

/**
 * Dockable manager for the function-centric taint models authored via {@link TaintModelDialog}.
 * Lists each model (enabled · function · role · port(s) · kind), lets the analyst toggle a model
 * on/off (only enabled models feed the query) or delete it. Backed by the live authored-models
 * list in {@link CTADLTaintState}.
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
		delete.setPopupMenuData(new docking.action.MenuData(new String[] { "Delete model" }));
		addLocalAction(delete);
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
