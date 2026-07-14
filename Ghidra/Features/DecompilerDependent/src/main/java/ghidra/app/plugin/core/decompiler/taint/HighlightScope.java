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

/**
 * Which SARIF result rule-IDs feed the taint highlight when the analyst applies results.
 * The scope narrows the over-broad "apply everything" behavior: a focused source→sink query
 * would otherwise light up every downstream tainted instruction, not just the path.
 *
 * <ul>
 * <li>{@link #PATHS} — {@code C0001} tainted-path code flows only (the focused default).</li>
 * <li>{@link #ALL_TAINTED} — {@code C0002} tainted instructions (the broad view).</li>
 * </ul>
 *
 * <p>There is deliberately no sources/sinks scope: ctadl-rs emits {@code C0003}/{@code C0004}
 * source/sink results as function-level markers with no instruction address, so they carry
 * nothing to highlight. Source/sink instructions are visible as the endpoints of {@link #PATHS}.
 */
public enum HighlightScope {
	PATHS("Paths"),
	ALL_TAINTED("All tainted");

	private final String label;

	HighlightScope(String label) {
		this.label = label;
	}

	/** Human-facing name for the scope control. */
	public String label() {
		return label;
	}

	/** True if a SARIF result with this rule-ID belongs to this scope. Null-safe. */
	public boolean matches(String ruleId) {
		if (ruleId == null) {
			return false;
		}
		return switch (this) {
			case PATHS -> ruleId.startsWith("C0001");
			case ALL_TAINTED -> ruleId.startsWith("C0002");
		};
	}
}
