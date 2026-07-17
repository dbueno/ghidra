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
public class IndexFreshnessTest {
  static int fails=0;
  static void check(String n, boolean c){ System.out.println((c?"ok: ":"FAIL: ")+n); if(!c) fails++; }
  public static void main(String[] a){
    IndexFreshness f = new IndexFreshness();
    check("starts in sync (not stale)", !f.isStale());
    f.onModelChanged(TaintModel.propagation(List.of("memcpy"),"Argument(1).deref","Argument(0).deref"));
    check("propagation change from fresh restales", f.isStale());
    f.markIndexed(); check("clean after index", !f.isStale());
    f.onModelChanged(TaintModel.source(List.of("recv"),"Argument(1).deref","user_input"));
    check("source change does not restale", !f.isStale());
    f.onModelChanged(TaintModel.propagation(List.of("memcpy"),"Argument(1).deref","Argument(0).deref"));
    check("propagation change restales", f.isStale());
    f.markIndexed();
    f.onModelSetStructurallyChanged();
    check("structural change restales", f.isStale());
    if(fails>0) System.exit(1);
  }
}
