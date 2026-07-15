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
import ghidra.program.model.pcode.HighFunction;

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
		// The ports backing each dropdown (parallel to the choices minus NONE). The input list
		// excludes the return value, so a selection is mapped back through its own list.
		final List<PortOption> inPorts;
		final List<PortOption> outPorts;
		final GCheckBox inDeref = new GCheckBox(".deref");
		final GCheckBox outDeref = new GCheckBox(".deref");

		PropRow(List<PortOption> inPorts, List<PortOption> outPorts) {
			this.inPorts = inPorts;
			this.outPorts = outPorts;
			in = new JComboBox<>(choicesFor(inPorts));
			out = new JComboBox<>(choicesFor(outPorts));
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
		this(function, null, List.of());
	}

	/**
	 * Picker with the decompiler's {@link HighFunction} so the port list can fall back to
	 * inferred parameters when {@code function} has no committed formal parameters.
	 */
	public TaintModelDialog(Function function, HighFunction hf) {
		this(function, hf, List.of());
	}

	/**
	 * Edit-in-place constructor: pre-fills the picker from {@code seed}, the existing models for
	 * this function, so the analyst can adjust them instead of deleting and re-adding. On OK the
	 * caller replaces the function's whole model set with {@link #getResult()}.
	 */
	public TaintModelDialog(Function function, List<TaintModel> seed) {
		this(function, null, seed);
	}

	/**
	 * Master constructor. {@code hf} (the decompiler's HighFunction for {@code function}, or
	 * {@code null}) lets the port list fall back to inferred parameters when the function has no
	 * committed formal parameters — see {@link FunctionPortResolver#portsOf(Function, HighFunction)}.
	 */
	public TaintModelDialog(Function function, HighFunction hf, List<TaintModel> seed) {
		super("Model taint for " + FunctionPortResolver.resolveTarget(function).getName());
		Function target = FunctionPortResolver.resolveTarget(function);
		this.functionName = target.getName();
		this.ports = FunctionPortResolver.portsOf(target, hf);
		addWorkPanel(buildPanel());
		addOKButton();
		addCancelButton();
		setOkButtonText(seed.isEmpty() ? "Add model" : "Update model");
		setResizable(true);
		applySeed(seed);
	}

	/** Pre-fill the grid and propagation rows from existing models (edit-in-place). */
	private void applySeed(List<TaintModel> seed) {
		for (TaintModel m : seed) {
			if (m.role() == TaintModel.Role.PROPAGATION) {
				seedPropagation(m);
			}
			else {
				seedEndpoint(m);
			}
		}
	}

	private void seedEndpoint(TaintModel m) {
		int i = portIndex(basePortOf(m.port()));
		if (i < 0) {
			return; // the port no longer exists on this function
		}
		// Set the role first (its listener defaults the kind); then override with the saved kind.
		roleCombos[i].setSelectedItem(m.role() == TaintModel.Role.SOURCE ? "source" : "sink");
		kindFields[i].setText(m.kind() == null ? "" : m.kind());
		derefChecks[i].setSelected(isDeref(m.port()));
	}

	private void seedPropagation(TaintModel m) {
		addPropRow();
		PropRow row = propRows.get(propRows.size() - 1);
		selectPort(row.in, row.inPorts, basePortOf(m.inputPort()));
		row.inDeref.setSelected(isDeref(m.inputPort()));
		selectPort(row.out, row.outPorts, basePortOf(m.outputPort()));
		row.outDeref.setSelected(isDeref(m.outputPort()));
	}

	/** Select the dropdown entry for {@code basePort} (leave on NONE if it is not in the list). */
	private void selectPort(JComboBox<String> combo, List<PortOption> ps, String basePort) {
		for (int i = 0; i < ps.size(); i++) {
			if (ps.get(i).basePort().equals(basePort)) {
				combo.setSelectedIndex(i + 1);
				return;
			}
		}
	}

	/** Grid row index whose port has this base port (e.g. "Argument(1)"), or -1 if none. */
	private int portIndex(String basePort) {
		for (int i = 0; i < ports.size(); i++) {
			if (ports.get(i).basePort().equals(basePort)) {
				return i;
			}
		}
		return -1;
	}

	private static boolean isDeref(String port) {
		return port != null && port.endsWith(".deref");
	}

	private static String basePortOf(String port) {
		if (port == null) {
			return "";
		}
		return port.endsWith(".deref") ? port.substring(0, port.length() - ".deref".length()) : port;
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
		sp.setPreferredSize(new Dimension(620, 64));
		sp.setBorder(BorderFactory.createEmptyBorder());
		prop.add(sp, BorderLayout.CENTER);

		JButton addPair = new JButton("+ Add pair");
		addPair.addActionListener(e -> addPropRow());
		JPanel addBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
		addBar.add(addPair);
		prop.add(addBar, BorderLayout.SOUTH);
		panel.add(prop, BorderLayout.SOUTH);

		// Start with no propagation rows — propagation is opt-in via "+ Add pair".

		// Let the layout compute the height so the Sources / Sinks grid always gets the room its
		// rows need (never cramped) and no empty vertical gap is created; the grid's own preferred
		// width already fits the longest label, so we only floor and cap the width. The dialog is
		// resizable, so a pathological signature can still be widened by hand.
		Dimension natural = panel.getPreferredSize();
		int width = Math.min(1040, Math.max(620, natural.width));
		panel.setPreferredSize(new Dimension(width, natural.height));
		return panel;
	}

	/**
	 * Dropdown labels for a propagation port list: {@code NONE} plus each port's analyst-facing
	 * name (e.g. "src", "param_1", "return") rather than the raw CTADL syntax ("Argument(0)"). The
	 * per-side {@code .deref} checkbox applies the C-style "*"; a selection is mapped back to its
	 * port through the same list, so friendlier labels are safe.
	 */
	private String[] choicesFor(List<PortOption> ps) {
		String[] ch = new String[ps.size() + 1];
		ch[0] = NONE;
		for (int i = 0; i < ps.size(); i++) {
			ch[i + 1] = ps.get(i).displayName();
		}
		return ch;
	}

	/** Ports eligible as a propagation <em>input</em>: everything except the return value. */
	private List<PortOption> inputPorts() {
		List<PortOption> in = new ArrayList<>();
		for (PortOption p : ports) {
			if (!"Return".equals(p.basePort())) {
				in.add(p);
			}
		}
		return in;
	}

	private void addPropRow() {
		// Input excludes the return (a return can't be a propagation source); output allows it.
		PropRow row = new PropRow(inputPorts(), ports);
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
				PortOption ip = row.inPorts.get(inIdx - 1);
				PortOption op = row.outPorts.get(outIdx - 1);
				String in = ip.portString(row.inDeref.isSelected());
				String out = op.portString(row.outDeref.isSelected());
				String inDisp = ip.displayPort(row.inDeref.isSelected());
				String outDisp = op.displayPort(row.outDeref.isSelected());
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
