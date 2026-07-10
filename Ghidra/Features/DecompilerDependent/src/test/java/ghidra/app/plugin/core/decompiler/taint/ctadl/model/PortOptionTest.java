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
    if(fails>0) System.exit(1);
  }
}
