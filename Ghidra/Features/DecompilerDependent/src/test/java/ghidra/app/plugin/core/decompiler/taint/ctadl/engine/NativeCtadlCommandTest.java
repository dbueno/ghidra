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
package ghidra.app.plugin.core.decompiler.taint.ctadl.engine;
import java.util.List;import java.util.Map;
public class NativeCtadlCommandTest {
  static int fails=0;
  static void check(String n, boolean c){ System.out.println((c?"ok: ":"FAIL: ")+n); if(!c) fails++; }
  public static void main(String[] a){
    check("import", NativeCtadlCommand.importCmd("/e/ctadl","prog","/f/facts")
      .equals(List.of("/e/ctadl","import","-l","pcode","-n","prog","/f/facts")));
    check("index no models", NativeCtadlCommand.indexCmd("/e/ctadl","prog",null)
      .equals(List.of("/e/ctadl","index","prog","prog")));
    check("index with models", NativeCtadlCommand.indexCmd("/e/ctadl","prog","/m/prop.jsonl")
      .equals(List.of("/e/ctadl","index","prog","prog","-m","/m/prop.jsonl")));
    check("query", NativeCtadlCommand.queryCmd("/e/ctadl","prog","/m/q.jsonl","/o/out.sarif")
      .equals(List.of("/e/ctadl","query","prog","-m","/m/q.jsonl","-o","/o/out.sarif","--sarif-profile","debug")));
    check("env set", NativeCtadlCommand.storeEnv("/s").equals(Map.of("XDG_STATE_HOME","/s")));
    check("env default empty", NativeCtadlCommand.storeEnv(null).isEmpty());
    if(fails>0) System.exit(1);
  }
}
