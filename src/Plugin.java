import jamiebalfour.zpe.core.*;
import jamiebalfour.zpe.interfaces.ZPECustomFunction;
import jamiebalfour.zpe.interfaces.ZPELibrary;

import java.util.HashMap;
import java.util.Map;

public class Plugin implements ZPELibrary {

  @Override
  public Map<String, ZPECustomFunction> getFunctions() {
    return null;
  }

  @Override
  public Map<String, Class<? extends ZPEStructure>> getObjects() {
    HashMap<String, Class<? extends ZPEStructure>> arr = new HashMap<>();
    arr.put("Vault", ZPEVaultObject.class);
    return arr;
  }

  @Override
  public boolean supportsWindows() {
    return true;
  }

  @Override
  public boolean supportsMacOs() {
    return true;
  }

  @Override
  public boolean supportsLinux() {
    return true;
  }

  @Override
  public String getName() {
    return "libVault";
  }

  @Override
  public String getVersionInfo() {
    return "1.0";
  }


}
