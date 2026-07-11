/* ###
 * IP: GHIDRA
 */
package ghidra.app.plugin.core.decompiler.taint.ctadl;

import java.awt.BorderLayout;
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
import resources.Icons;

/**
 * Dockable manager for the function-centric taint models authored via {@link TaintModelDialog}.
 * Lists each model (enabled · function · role · port(s) · kind), lets the analyst toggle a model
 * on/off (only enabled models feed the query) or delete it. Backed by the live authored-models
 * list in {@link CTADLTaintState}.
 */
public class TaintModelPanel extends ComponentProviderAdapter {

	private final TaintPlugin plugin;
	private final JComponent mainPanel;
	private final ModelTableModel tableModel;
	private final GTable table;

	public TaintModelPanel(TaintPlugin plugin) {
		super(plugin.getTool(), "Taint Models", plugin.getName());
		this.plugin = plugin;
		setTitle("Taint Models");

		tableModel = new ModelTableModel();
		table = new GTable(tableModel);
		table.getColumnModel().getColumn(0).setMaxWidth(60); // Enabled checkbox

		mainPanel = new JPanel(new BorderLayout());
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
					models.remove(row);
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

	/** The live authored-models list from the current ctadl state (empty if not ctadl). */
	private List<TaintModel> currentModels() {
		TaintState s = plugin.getTaintState();
		if (s instanceof CTADLTaintState c) {
			return c.getAuthoredModels();
		}
		return List.of();
	}

	/** Refresh the table from the backing list; shows the panel if hidden. */
	public void refresh() {
		tableModel.fireTableDataChanged();
		setSubTitle(currentModels().size() + " model(s)");
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
						? m.inputPort() + " → " + m.outputPort()
						: m.port();
				case 4 -> m.role() == TaintModel.Role.PROPAGATION ? "" : m.kind();
				default -> "";
			};
		}

		@Override
		public void setValueAt(Object value, int row, int col) {
			if (col == 0) {
				currentModels().get(row).setEnabled((Boolean) value);
				fireTableCellUpdated(row, col);
			}
		}
	}
}
