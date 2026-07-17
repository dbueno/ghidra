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
public final class ModelJsonlWriter {
  private ModelJsonlWriter(){}
  public static String toJsonl(List<TaintModel> models, TaintModel.Destination dest) {
    StringBuilder sb = new StringBuilder();
    for (TaintModel m : models) {
      if (!m.enabled() || m.destination() != dest) continue;
      sb.append("{\"find\":\"methods\",\"where\":[{\"constraint\":\"signature_match\",\"names\":[");
      List<String> fns = m.functionNames();
      for (int i=0;i<fns.size();i++){ if(i>0) sb.append(','); sb.append('"').append(esc(fns.get(i))).append('"'); }
      sb.append("]}],\"model\":{");
      switch (m.role()) {
        case SOURCE -> sb.append("\"sources\":[{\"port\":\"").append(esc(m.port())).append("\",\"kind\":\"").append(esc(m.kind())).append("\"}]");
        case SINK   -> sb.append("\"sinks\":[{\"port\":\"").append(esc(m.port())).append("\",\"kind\":\"").append(esc(m.kind())).append("\"}]");
        case PROPAGATION -> sb.append("\"propagation\":[{\"input\":\"").append(esc(m.inputPort())).append("\",\"output\":\"").append(esc(m.outputPort())).append("\"}]");
      }
      sb.append("}}\n");
    }
    return sb.toString();
  }
  private static String esc(String s){
    StringBuilder b = new StringBuilder();
    for (int i=0;i<s.length();i++){ char c=s.charAt(i);
      switch(c){ case '"'->b.append("\\\""); case '\\'->b.append("\\\\"); case '\n'->b.append("\\n"); case '\r'->b.append("\\r"); case '\t'->b.append("\\t");
        default -> { if(c<0x20) b.append(String.format("\\u%04x",(int)c)); else b.append(c);} }
    }
    return b.toString();
  }
}
