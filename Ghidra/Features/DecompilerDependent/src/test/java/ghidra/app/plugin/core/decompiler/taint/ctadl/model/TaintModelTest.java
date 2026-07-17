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
public class TaintModelTest {
  static int fails=0;
  static void check(String n, boolean c){ System.out.println((c?"ok: ":"FAIL: ")+n); if(!c) fails++; }
  public static void main(String[] a){
    TaintModel src = TaintModel.source(List.of("recv","recvfrom"), "Argument(1).deref", "user_input");
    check("src role", src.role()==TaintModel.Role.SOURCE);
    check("src dest QUERY", src.destination()==TaintModel.Destination.QUERY);
    check("src names", src.functionNames().equals(List.of("recv","recvfrom")));
    check("src port", src.port().equals("Argument(1).deref"));
    check("src default enabled", src.enabled());
    TaintModel snk = TaintModel.sink(List.of("strcpy"), "Argument(1).deref", "buffer_overflow");
    check("sink role", snk.role()==TaintModel.Role.SINK);
    check("sink dest QUERY", snk.destination()==TaintModel.Destination.QUERY);
    TaintModel prop = TaintModel.propagation(List.of("memcpy"), "Argument(1).deref", "Argument(0).deref");
    check("prop role", prop.role()==TaintModel.Role.PROPAGATION);
    check("prop dest INDEX", prop.destination()==TaintModel.Destination.INDEX);
    check("prop in", prop.inputPort().equals("Argument(1).deref"));
    check("prop out", prop.outputPort().equals("Argument(0).deref"));
    prop.setEnabled(false); check("toggle", !prop.enabled());
    if(fails>0) System.exit(1);
  }
}
