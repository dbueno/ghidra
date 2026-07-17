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
public class PortOptionTest {
  static int fails=0;
  static void check(String n, boolean c){ System.out.println((c?"ok: ":"FAIL: ")+n); if(!c) fails++; }
  public static void main(String[] a){
    PortOption ret = new PortOption("return: int", "Return", false);
    check("ret plain", ret.portString(false).equals("Return"));
    check("ret deref", ret.portString(true).equals("Return.deref"));
    check("ret not pointer", !ret.pointer());
    PortOption buf = new PortOption("arg1: char* buf", "Argument(1)", true);
    check("arg plain", buf.portString(false).equals("Argument(1)"));
    check("arg deref", buf.portString(true).equals("Argument(1).deref"));
    check("arg pointer", buf.pointer());
    check("label", buf.label().equals("arg1: char* buf"));
    PortOption src = new PortOption("arg1: char * src", "Argument(1)", true, "src");
    check("displayName", src.displayName().equals("src"));
    check("displayPort deref", src.displayPort(true).equals("*src"));
    check("displayPort plain", src.displayPort(false).equals("src"));
    PortOption ret2 = new PortOption("return: char *", "Return", true, "return");
    check("ret display deref", ret2.displayPort(true).equals("*return"));
    // 3-arg ctor still works, displayName falls back to basePort:
    PortOption legacy = new PortOption("arg0: int n", "Argument(0)", false);
    check("legacy displayName == basePort", legacy.displayName().equals("Argument(0)"));
    check("legacy displayPort plain == basePort", legacy.displayPort(false).equals("Argument(0)"));
    if(fails>0) System.exit(1);
  }
}
