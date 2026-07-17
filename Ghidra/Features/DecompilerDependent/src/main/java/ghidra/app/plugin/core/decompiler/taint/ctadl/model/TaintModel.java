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
public final class TaintModel {
  public enum Role { SOURCE, SINK, PROPAGATION }
  public enum Destination { INDEX, QUERY }
  private final List<String> functionNames;
  private final Role role;
  private final String port;       // source/sink
  private final String kind;       // source/sink
  private final String inputPort;  // propagation
  private final String outputPort; // propagation
  private final String portDisplay;   // source/sink (nullable)
  private final String inputDisplay;  // propagation (nullable)
  private final String outputDisplay; // propagation (nullable)
  private boolean enabled = true;
  private TaintModel(List<String> fns, Role r, String port, String kind, String in, String out,
      String portDisplay, String inputDisplay, String outputDisplay) {
    this.functionNames = List.copyOf(fns); this.role = r;
    this.port = port; this.kind = kind; this.inputPort = in; this.outputPort = out;
    this.portDisplay = portDisplay; this.inputDisplay = inputDisplay; this.outputDisplay = outputDisplay;
  }
  public static TaintModel source(List<String> fns, String port, String kind){ return source(fns, port, kind, null); }
  public static TaintModel source(List<String> fns, String port, String kind, String portDisplay){
    return new TaintModel(fns, Role.SOURCE, port, kind, null, null, portDisplay, null, null); }
  public static TaintModel sink(List<String> fns, String port, String kind){ return sink(fns, port, kind, null); }
  public static TaintModel sink(List<String> fns, String port, String kind, String portDisplay){
    return new TaintModel(fns, Role.SINK, port, kind, null, null, portDisplay, null, null); }
  public static TaintModel propagation(List<String> fns, String in, String out){ return propagation(fns, in, out, null, null); }
  public static TaintModel propagation(List<String> fns, String in, String out, String inDisplay, String outDisplay){
    return new TaintModel(fns, Role.PROPAGATION, null, null, in, out, null, inDisplay, outDisplay); }
  public List<String> functionNames(){ return functionNames; }
  public Role role(){ return role; }
  public String port(){ return port; }
  public String kind(){ return kind; }
  public String inputPort(){ return inputPort; }
  public String outputPort(){ return outputPort; }
  public String portDisplay(){ return portDisplay; }
  public String inputDisplay(){ return inputDisplay; }
  public String outputDisplay(){ return outputDisplay; }
  public boolean enabled(){ return enabled; }
  public void setEnabled(boolean e){ this.enabled = e; }
  public Destination destination(){ return role == Role.PROPAGATION ? Destination.INDEX : Destination.QUERY; }
}
