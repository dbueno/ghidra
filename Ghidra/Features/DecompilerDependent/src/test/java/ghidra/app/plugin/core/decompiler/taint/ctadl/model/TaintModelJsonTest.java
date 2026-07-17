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
import java.util.List;
public class TaintModelJsonTest {
  static int fails=0;
  static void check(String n, boolean c){ System.out.println((c?"ok: ":"FAIL: ")+n); if(!c) fails++; }
  public static void main(String[] a){
    var src = TaintModel.source(List.of("recv","recvfrom"), "Argument(1).deref", "user_input");
    var snk = TaintModel.sink(List.of("strcpy"), "Argument(1).deref", "buffer_overflow");
    var prop = TaintModel.propagation(List.of("memcpy"), "Argument(1).deref", "Argument(0).deref");
    var disabled = TaintModel.sink(List.of("system"), "Argument(0).deref", "command_injection");
    disabled.setEnabled(false);

    String json = TaintModelJson.export(List.of(src, snk, prop, disabled));
    check("export includes disabled model", json.contains("system"));
    check("export has model_generators", json.contains("\"model_generators\""));
    check("export sources", json.contains("\"sources\""));
    check("export sinks", json.contains("\"sinks\""));
    check("export propagation in/out", json.contains("\"input\"") && json.contains("\"output\""));

    List<TaintModel> back = TaintModelJson.importModels(json, TaintModelJson.NO_DISPLAY);
    check("round-trip count", back.size()==4);
    check("recv names kept", back.get(0).functionNames().equals(List.of("recv","recvfrom")));
    check("recv port", back.get(0).port().equals("Argument(1).deref"));
    check("recv kind", back.get(0).kind().equals("user_input"));
    check("recv role SOURCE", back.get(0).role()==TaintModel.Role.SOURCE);
    check("raw display null", back.get(0).portDisplay()==null);
    check("all imported enabled", back.stream().allMatch(TaintModel::enabled));
    var propBack = back.stream().filter(m -> m.role()==TaintModel.Role.PROPAGATION).findFirst().orElseThrow();
    check("prop in/out", propBack.inputPort().equals("Argument(1).deref") && propBack.outputPort().equals("Argument(0).deref"));

    TaintModelJson.DisplayResolver stub =
      (fn, port) -> ("recv".equals(fn) && "Argument(1).deref".equals(port)) ? "*buf" : null;
    List<TaintModel> withDisp = TaintModelJson.importModels(TaintModelJson.export(List.of(src)), stub);
    check("display reconstructed", "*buf".equals(withDisp.get(0).portDisplay()));

    String twoEp = "{\"model_generators\":[{\"find\":\"methods\",\"where\":[{\"constraint\":\"signature_match\",\"names\":[\"f\"]}],\"model\":{\"sources\":[{\"port\":\"Argument(0)\",\"kind\":\"k1\"},{\"port\":\"Argument(1)\",\"kind\":\"k2\"}]}}]}";
    List<TaintModel> fan = TaintModelJson.importModels(twoEp, TaintModelJson.NO_DISPLAY);
    check("fan-out two endpoints", fan.size()==2 && fan.get(0).port().equals("Argument(0)") && fan.get(1).port().equals("Argument(1)"));

    String jsonl = "{\"find\":\"methods\",\"where\":[{\"constraint\":\"signature_match\",\"names\":[\"a\"]}],\"model\":{\"sinks\":[{\"port\":\"Return\",\"kind\":\"k\"}]}}\n{\"find\":\"methods\",\"where\":[{\"constraint\":\"signature_match\",\"names\":[\"b\"]}],\"model\":{\"sinks\":[{\"port\":\"Return\",\"kind\":\"k\"}]}}";
    check("jsonl two generators", TaintModelJson.importModels(jsonl, TaintModelJson.NO_DISPLAY).size()==2);

    String addr = "{\"model_generators\":[{\"find\":\"instructions\",\"where\":[{\"constraint\":\"address\",\"value\":\"0x1000\"}],\"model\":{\"sources\":[{\"kind\":\"k\"}]}}]}";
    check("address generator skipped", TaintModelJson.importModels(addr, TaintModelJson.NO_DISPLAY).isEmpty());

    boolean threw=false;
    try { TaintModelJson.importModels("this is not json", TaintModelJson.NO_DISPLAY); }
    catch (RuntimeException ex){ threw=true; }
    check("malformed throws", threw);

    check("empty input empty result", TaintModelJson.importModels("", TaintModelJson.NO_DISPLAY).isEmpty());

    if(fails>0) System.exit(1);
  }
}
