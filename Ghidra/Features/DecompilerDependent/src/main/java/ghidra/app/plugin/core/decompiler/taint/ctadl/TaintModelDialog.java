/* ###
 * IP: GHIDRA
 */
package ghidra.app.plugin.core.decompiler.taint.ctadl;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GLabel;
import ghidra.app.plugin.core.decompiler.taint.ctadl.model.PortOption;
import ghidra.app.plugin.core.decompiler.taint.ctadl.model.TaintModel;
import ghidra.program.model.listing.Function;

/**
 * Function-centric picker: given a resolved {@link Function}, lets the analyst assign each
 * port (return + parameters) as a taint <b>source</b> or <b>sink</b> (with a kind), and/or
 * declare one or more <b>propagation</b> {@code input → output} pairs. Pointer ports default
 * to {@code .deref} (contents). On OK, {@link #getResult()} returns the authored
 * {@link TaintModel}s. Modal: show via {@code tool.showDialog(dialog)} then read
 * {@link #getResult()} (empty on cancel).
 */
public class TaintModelDialog extends DialogComponentProvider {

	private static final String NONE = "—"; // em dash

	private final String functionName;
	private final List<PortOption> ports;

	private JComboBox<String>[] roleCombos;
	private JTextField[] kindFields;
	private GCheckBox[] derefChecks;

	private JPanel propRowsPanel;
	private final List<PropRow> propRows = new ArrayList<>();

	private final List<TaintModel> result = new ArrayList<>();
	private boolean cancelled = true;

	/** One propagation {@code input → output} pair in the (repeatable) propagation section. */
	private class PropRow {
		final JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
		final JComboBox<String> in;
		final JComboBox<String> out;
		final GCheckBox inDeref = new GCheckBox(".deref");
		final GCheckBox outDeref = new GCheckBox(".deref");

		PropRow(String[] choices) {
			in = new JComboBox<>(choices);
			out = new JComboBox<>(choices);
			inDeref.setSelected(true);
			outDeref.setSelected(true);
			JButton remove = new JButton("Remove");
			remove.addActionListener(e -> removePropRow(this));
			panel.add(new GLabel("input:"));
			panel.add(in);
			panel.add(inDeref);
			panel.add(new GLabel("→ output:"));
			panel.add(out);
			panel.add(outDeref);
			panel.add(remove);
		}
	}

	public TaintModelDialog(Function function) {
		super("Model taint for " + FunctionPortResolver.resolveTarget(function).getName());
		Function target = FunctionPortResolver.resolveTarget(function);
		this.functionName = target.getName();
		this.ports = FunctionPortResolver.portsOf(target);
		addWorkPanel(buildPanel());
		addOKButton();
		addCancelButton();
		setOkButtonText("Add model");
	}

	@SuppressWarnings("unchecked")
	private JComponent buildPanel() {
		JPanel panel = new JPanel(new BorderLayout(10, 10));
		panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
		panel.add(new GLabel("Function: " + functionName), BorderLayout.NORTH);

		// --- Endpoints grid: Port | Role | Kind | contents(.deref) ---
		JPanel grid = new JPanel(new GridBagLayout());
		grid.setBorder(BorderFactory.createTitledBorder("Sources / Sinks"));

		place(grid, new GLabel("Port"), 0, 0, 0);
		place(grid, new GLabel("Role"), 1, 0, 0);
		place(grid, new GLabel("Kind"), 2, 0, 1.0);
		place(grid, new GLabel("contents (.deref)"), 3, 0, 0);

		int n = ports.size();
		roleCombos = new JComboBox[n];
		kindFields = new JTextField[n];
		derefChecks = new GCheckBox[n];

		for (int i = 0; i < n; i++) {
			PortOption p = ports.get(i);
			JComboBox<String> role = new JComboBox<>(new String[] { NONE, "source", "sink" });
			JTextField kind = new JTextField(22);
			GCheckBox deref = new GCheckBox();
			deref.setSelected(p.pointer());
			deref.setHorizontalAlignment(SwingConstants.CENTER);

			// Fill a sensible default kind when a role is chosen and the field is empty.
			role.addActionListener(e -> {
				String r = (String) role.getSelectedItem();
				if (kind.getText().isBlank()) {
					if ("source".equals(r)) {
						kind.setText("user_input");
					}
					else if ("sink".equals(r)) {
						kind.setText("buffer_overflow");
					}
				}
			});

			roleCombos[i] = role;
			kindFields[i] = kind;
			derefChecks[i] = deref;
			place(grid, new GLabel(p.label()), 0, i + 1, 0);
			place(grid, role, 1, i + 1, 0);
			place(grid, kind, 2, i + 1, 1.0);
			place(grid, deref, 3, i + 1, 0);
		}
		panel.add(grid, BorderLayout.CENTER);

		// --- Propagation: repeatable input -> output rows ---
		JPanel prop = new JPanel(new BorderLayout(0, 4));
		prop.setBorder(BorderFactory.createTitledBorder("Propagation (optional)"));
		propRowsPanel = new JPanel();
		propRowsPanel.setLayout(new BoxLayout(propRowsPanel, BoxLayout.Y_AXIS));
		JScrollPane sp = new JScrollPane(propRowsPanel,
			ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
			ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		sp.setPreferredSize(new Dimension(620, 86));
		sp.setBorder(BorderFactory.createEmptyBorder());
		prop.add(sp, BorderLayout.CENTER);

		JButton addPair = new JButton("+ Add pair");
		addPair.addActionListener(e -> addPropRow());
		JPanel addBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
		addBar.add(addPair);
		prop.add(addBar, BorderLayout.SOUTH);
		panel.add(prop, BorderLayout.SOUTH);

		// Start with no propagation rows — propagation is opt-in via "+ Add pair".

		int height = 40 + (n + 1) * 30 + 150;
		panel.setPreferredSize(new Dimension(660, height));
		return panel;
	}

	private String[] propChoices() {
		String[] ch = new String[ports.size() + 1];
		ch[0] = NONE;
		for (int i = 0; i < ports.size(); i++) {
			ch[i + 1] = ports.get(i).basePort();
		}
		return ch;
	}

	private void addPropRow() {
		PropRow row = new PropRow(propChoices());
		propRows.add(row);
		propRowsPanel.add(row.panel);
		propRowsPanel.revalidate();
		propRowsPanel.repaint();
	}

	private void removePropRow(PropRow row) {
		propRows.remove(row);
		propRowsPanel.remove(row.panel);
		propRowsPanel.revalidate();
		propRowsPanel.repaint();
	}

	/**
	 * Place a component in the endpoints grid at (col,row). {@code weightx > 0} makes the
	 * cell grow horizontally and fill (used for the Kind column so the field is not squeezed).
	 */
	private void place(JPanel grid, JComponent comp, int col, int row, double weightx) {
		GridBagConstraints c = new GridBagConstraints();
		c.gridx = col;
		c.gridy = row;
		c.insets = new Insets(3, 6, 3, 6);
		c.anchor = GridBagConstraints.WEST;
		c.weightx = weightx;
		c.fill = weightx > 0 ? GridBagConstraints.HORIZONTAL : GridBagConstraints.NONE;
		grid.add(comp, c);
	}

	@Override
	protected void okCallback() {
		result.clear();
		List<String> fn = List.of(functionName);

		for (int i = 0; i < ports.size(); i++) {
			String role = (String) roleCombos[i].getSelectedItem();
			if (NONE.equals(role)) {
				continue;
			}
			String port = ports.get(i).portString(derefChecks[i].isSelected());
			String portDisp = ports.get(i).displayPort(derefChecks[i].isSelected());
			String kind = kindFields[i].getText().isBlank()
					? ("source".equals(role) ? "user_input" : "buffer_overflow")
					: kindFields[i].getText().trim();
			if ("source".equals(role)) {
				result.add(TaintModel.source(fn, port, kind, portDisp));
			}
			else {
				result.add(TaintModel.sink(fn, port, kind, portDisp));
			}
		}

		for (PropRow row : propRows) {
			int inIdx = row.in.getSelectedIndex();
			int outIdx = row.out.getSelectedIndex();
			if (inIdx > 0 && outIdx > 0) {
				String in = ports.get(inIdx - 1).portString(row.inDeref.isSelected());
				String out = ports.get(outIdx - 1).portString(row.outDeref.isSelected());
				String inDisp = ports.get(inIdx - 1).displayPort(row.inDeref.isSelected());
				String outDisp = ports.get(outIdx - 1).displayPort(row.outDeref.isSelected());
				result.add(TaintModel.propagation(fn, in, out, inDisp, outDisp));
			}
		}

		if (result.isEmpty()) {
			setStatusText("Select at least one source, sink, or propagation pair.");
			return;
		}
		cancelled = false;
		close();
	}

	@Override
	protected void cancelCallback() {
		cancelled = true;
		close();
	}

	public boolean isCancelled() {
		return cancelled;
	}

	/** The models the analyst authored; empty if cancelled. */
	public List<TaintModel> getResult() {
		return result;
	}
}
