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

public class HighlightScopeTest {
  static int fails=0;
  static void check(String n, boolean c){ System.out.println((c?"ok: ":"FAIL: ")+n); if(!c) fails++; }
  public static void main(String[] a){
    check("PATHS matches C0001", HighlightScope.PATHS.matches("C0001.tainted-path"));
    check("PATHS rejects C0002", !HighlightScope.PATHS.matches("C0002.tainted-instruction"));
    check("ALL_TAINTED matches C0002", HighlightScope.ALL_TAINTED.matches("C0002.tainted-instruction"));
    check("ALL_TAINTED rejects C0001", !HighlightScope.ALL_TAINTED.matches("C0001.tainted-path"));
    check("ALL_TAINTED rejects C0003", !HighlightScope.ALL_TAINTED.matches("C0003.taint-source"));
    check("PATHS rejects C0004", !HighlightScope.PATHS.matches("C0004.taint-sink"));
    check("null safe", !HighlightScope.PATHS.matches(null));
    check("PATHS label", HighlightScope.PATHS.label().equals("Paths"));
    if(fails>0) System.exit(1);
  }
}
