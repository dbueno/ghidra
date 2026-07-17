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
public final class PortOption {
  private final String label; private final String basePort; private final boolean pointer;
  private final String displayName;
  public PortOption(String label, String basePort, boolean pointer){ this(label, basePort, pointer, basePort); }
  public PortOption(String label, String basePort, boolean pointer, String displayName){
    this.label=label; this.basePort=basePort; this.pointer=pointer; this.displayName=displayName; }
  public String label(){ return label; }
  public String basePort(){ return basePort; }
  public boolean pointer(){ return pointer; }
  public String displayName(){ return displayName; }
  public String portString(boolean deref){ return deref ? basePort + ".deref" : basePort; }
  public String displayPort(boolean deref){ return (deref ? "*" : "") + displayName; }
}
