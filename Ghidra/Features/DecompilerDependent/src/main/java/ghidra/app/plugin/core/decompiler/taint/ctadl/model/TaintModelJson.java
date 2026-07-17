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
package ghidra.app.plugin.core.decompiler.taint.ctadl.model;

import java.util.ArrayList;
import java.util.List;

import com.google.gson.*;

/**
 * JSON codec for authored taint {@link TaintModel}s in the ctadl engine's model-generator
 * format ({@code {model_generators:[{find,where,model}]}}) — the same shape the CLI consumes
 * via {@code -m} and {@link ghidra.app.plugin.core.decompiler.taint.ctadl.CTADLTaintState}
 * writes for a query. Export emits every model (enabled and disabled — the CLI format has no
 * enabled flag, so it is dropped); import parses the format, fans each generator out into one
 * model per endpoint (its function-name list is kept on every fanned-out model), and
 * reconstructs the cosmetic port display via a caller-supplied {@link DisplayResolver}
 * (null-tolerant: a null result keeps the raw port token as the label).
 */
public final class TaintModelJson {
	private TaintModelJson() {
	}

	/** Reconstructs a model's cosmetic port label from its function name and raw port token. */
	@FunctionalInterface
	public interface DisplayResolver {
		/** The display label for {@code portToken} on {@code functionName}, or null for the raw token. */
		String resolve(String functionName, String portToken);
	}

	/** A resolver that always falls back to the raw token (used when no program is available). */
	public static final DisplayResolver NO_DISPLAY = (fn, port) -> null;

	/**
	 * Serializes {@code models} (all of them, regardless of {@link TaintModel#enabled()}) as a
	 * pretty-printed {@code {model_generators:[...]}} document, one {@code find:"methods"}
	 * generator per model. CLI-feedable via {@code ctadl ... -m}.
	 */
	public static String export(List<TaintModel> models) {
		JsonArray generators = new JsonArray();
		for (TaintModel m : models) {
			generators.add(toGenerator(m));
		}
		JsonObject root = new JsonObject();
		root.add("model_generators", generators);
		return new GsonBuilder().setPrettyPrinting().create().toJson(root);
	}

	private static JsonObject toGenerator(TaintModel m) {
		JsonArray names = new JsonArray();
		for (String fn : m.functionNames()) {
			names.add(fn);
		}
		JsonObject sig = new JsonObject();
		sig.addProperty("constraint", "signature_match");
		sig.add("names", names);
		JsonArray where = new JsonArray();
		where.add(sig);

		JsonArray endpoints = new JsonArray();
		JsonObject ep = new JsonObject();
		JsonObject model = new JsonObject();
		switch (m.role()) {
			case SOURCE -> {
				ep.addProperty("port", m.port());
				ep.addProperty("kind", m.kind());
				endpoints.add(ep);
				model.add("sources", endpoints);
			}
			case SINK -> {
				ep.addProperty("port", m.port());
				ep.addProperty("kind", m.kind());
				endpoints.add(ep);
				model.add("sinks", endpoints);
			}
			case PROPAGATION -> {
				ep.addProperty("input", m.inputPort());
				ep.addProperty("output", m.outputPort());
				endpoints.add(ep);
				model.add("propagation", endpoints);
			}
		}

		JsonObject gen = new JsonObject();
		gen.addProperty("find", "methods");
		gen.add("where", where);
		gen.add("model", model);
		return gen;
	}

	/**
	 * Parses {@code json} — a {@code {model_generators:[...]}} object, a bare array of
	 * generators, a single generator object, or newline-delimited generators (JSONL) — into
	 * models, fanning each generator out into one model per endpoint. {@code resolver}
	 * reconstructs each model's cosmetic port display (pass {@link #NO_DISPLAY} for raw tokens).
	 * Generators without a {@code signature_match} {@code names} list (e.g. address/instruction
	 * generators) are skipped. Throws {@link RuntimeException} (Gson {@code JsonParseException})
	 * on malformed input — the caller imports nothing.
	 */
	public static List<TaintModel> importModels(String json, DisplayResolver resolver) {
		List<TaintModel> out = new ArrayList<>();
		for (JsonObject gen : generatorsOf(json)) {
			List<String> names = namesOf(gen);
			if (names.isEmpty()) {
				continue; // not a signature_match generator (e.g. address/instruction based)
			}
			if (!gen.has("model") || !gen.get("model").isJsonObject()) {
				continue;
			}
			JsonObject model = gen.getAsJsonObject("model");
			String first = names.get(0);
			if (model.has("sources")) {
				for (JsonElement e : model.getAsJsonArray("sources")) {
					JsonObject o = e.getAsJsonObject();
					String port = str(o, "port");
					out.add(TaintModel.source(names, port, str(o, "kind"), resolver.resolve(first, port)));
				}
			}
			if (model.has("sinks")) {
				for (JsonElement e : model.getAsJsonArray("sinks")) {
					JsonObject o = e.getAsJsonObject();
					String port = str(o, "port");
					out.add(TaintModel.sink(names, port, str(o, "kind"), resolver.resolve(first, port)));
				}
			}
			if (model.has("propagation")) {
				for (JsonElement e : model.getAsJsonArray("propagation")) {
					JsonObject o = e.getAsJsonObject();
					String in = str(o, "input");
					String outPort = str(o, "output");
					out.add(TaintModel.propagation(names, in, outPort,
						resolver.resolve(first, in), resolver.resolve(first, outPort)));
				}
			}
		}
		return out;
	}

	/**
	 * Accepts a {@code {model_generators:[...]}} object, a bare array, a single generator object,
	 * or JSONL (one generator object per line); returns the generator objects.
	 */
	private static List<JsonObject> generatorsOf(String json) {
		List<JsonObject> gens = new ArrayList<>();
		String trimmed = json == null ? "" : json.strip();
		if (trimmed.isEmpty()) {
			return gens;
		}
		JsonElement root;
		try {
			root = JsonParser.parseString(trimmed);
		}
		catch (JsonSyntaxException multipleTopLevel) {
			// JSONL: multiple top-level objects, one generator per non-blank line.
			for (String line : trimmed.split("\n")) {
				String s = line.strip();
				if (!s.isEmpty()) {
					gens.add(JsonParser.parseString(s).getAsJsonObject());
				}
			}
			return gens;
		}
		JsonArray arr;
		if (root.isJsonObject() && root.getAsJsonObject().has("model_generators")) {
			arr = root.getAsJsonObject().getAsJsonArray("model_generators");
		}
		else if (root.isJsonArray()) {
			arr = root.getAsJsonArray();
		}
		else {
			arr = new JsonArray();
			arr.add(root); // a single bare generator object
		}
		for (JsonElement e : arr) {
			gens.add(e.getAsJsonObject());
		}
		return gens;
	}

	private static List<String> namesOf(JsonObject gen) {
		List<String> names = new ArrayList<>();
		if (!gen.has("where") || !gen.get("where").isJsonArray()) {
			return names;
		}
		for (JsonElement e : gen.getAsJsonArray("where")) {
			JsonObject c = e.getAsJsonObject();
			if ("signature_match".equals(str(c, "constraint")) && c.has("names")) {
				for (JsonElement n : c.getAsJsonArray("names")) {
					names.add(n.getAsString());
				}
			}
		}
		return names;
	}

	private static String str(JsonObject o, String k) {
		return o.has(k) && !o.get(k).isJsonNull() ? o.get(k).getAsString() : null;
	}
}
