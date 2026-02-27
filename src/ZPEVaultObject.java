import jamiebalfour.generic.JBBinarySearchTree;
import jamiebalfour.zpe.core.ZPECore;
import jamiebalfour.zpe.core.ZPEObject;
import jamiebalfour.zpe.core.ZPERuntimeEnvironment;
import jamiebalfour.zpe.core.ZPEStructure;
import jamiebalfour.zpe.interfaces.ZPEPropertyWrapper;
import jamiebalfour.zpe.interfaces.ZPEType;
import jamiebalfour.zpe.types.ZPEBoolean;
import jamiebalfour.zpe.types.ZPEList;
import jamiebalfour.zpe.types.ZPEString;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.*;

/**
 * ZPE Security Object
 * <p>
 * Example YASS usage (conceptually):
 * s = new Security()
 * s.init("passphrase")
 * s.set("token", "abc")
 * print(s.get("token"))
 * s.close()
 */
public class ZPEVaultObject extends ZPEStructure {

  private static final long serialVersionUID = 2951605849804471428L;

  // ---- Crypto params ----
  private static final int VERSION = 1;
  private static final int SALT_LEN = 16;
  private static final int IV_LEN = 12;
  private static final int GCM_TAG_BITS = 128;
  private static final int KEY_BITS = 256;
  private static final int PBKDF2_ITERATIONS = 200_000;

  private final SecureRandom rng = new SecureRandom();
  // Store (dependency-free)
  private final Properties store = new Properties();
  // Session state
  private SecretKey sessionKey = null;
  private byte[] salt = null;
  private Path storePath = null;

  public ZPEVaultObject(ZPERuntimeEnvironment z, ZPEPropertyWrapper parent) {
    super(z, parent, "Security");

    addNativeMethod("init", new init_Command());
    addNativeMethod("set", new set_Command());
    addNativeMethod("get", new get_Command());
    addNativeMethod("has", new has_Command());
    addNativeMethod("delete", new delete_Command());
    addNativeMethod("list_keys", new list_keys_Command());
    addNativeMethod("close", new close_Command());
  }

  // ---------------- Public API (called by native methods) ----------------

  private static String entryIvKey(String key) {
    return "entry." + key + ".iv";
  }

  private static String entryCtKey(String key) {
    return "entry." + key + ".ct";
  }

  public boolean init(String passphrase) {
    try {
      ensureStorePath();

      if (Files.exists(storePath)) {
        loadStore();
        String saltB64 = store.getProperty("kdf.salt");
        String iterStr = store.getProperty("kdf.iter");
        if (saltB64 == null || iterStr == null) {
          ZPECore.log("Security: store corrupt (missing KDF params).");
          return false;
        }

        salt = Base64.getDecoder().decode(saltB64);

        int iter;
        try {
          iter = Integer.parseInt(iterStr);
        } catch (NumberFormatException e) {
          ZPECore.log("Security: store corrupt (bad iteration count).");
          return false;
        }

        sessionKey = deriveKey(passphrase, salt, iter);
        return true;
      } else {
        // Create new store
        salt = new byte[SALT_LEN];
        rng.nextBytes(salt);

        store.clear();
        store.setProperty("version", String.valueOf(VERSION));
        store.setProperty("kdf.salt", Base64.getEncoder().encodeToString(salt));
        store.setProperty("kdf.iter", String.valueOf(PBKDF2_ITERATIONS));

        sessionKey = deriveKey(passphrase, salt, PBKDF2_ITERATIONS);
        persistStore();
        return true;
      }
    } catch (Exception e) {
      ZPECore.log("Security init failed: " + e.getMessage());
      return false;
    }
  }

  public boolean close() {
    try {
      wipeKey();
      return true;
    } catch (Exception e) {
      ZPECore.log("Security close failed: " + e.getMessage());
      return false;
    }
  }

  public boolean has(String key) {
    try {
      requireInit();
      return store.containsKey(entryIvKey(key)) && store.containsKey(entryCtKey(key));
    } catch (Exception e) {
      return false;
    }
  }

  public boolean delete(String key) {
    try {
      requireInit();
      boolean existed = has(key);
      store.remove(entryIvKey(key));
      store.remove(entryCtKey(key));
      if (existed) persistStore();
      return existed;
    } catch (Exception e) {
      ZPECore.log("Security delete failed: " + e.getMessage());
      return false;
    }
  }

  public boolean set(String key, String value) {
    try {
      requireInit();

      byte[] iv = new byte[IV_LEN];
      rng.nextBytes(iv);

      byte[] pt = value.getBytes(StandardCharsets.UTF_8);
      byte[] ct = aesGcmEncrypt(sessionKey, iv, pt);

      store.setProperty(entryIvKey(key), Base64.getEncoder().encodeToString(iv));
      store.setProperty(entryCtKey(key), Base64.getEncoder().encodeToString(ct));

      persistStore();
      return true;
    } catch (Exception e) {
      ZPECore.log("Security set failed: " + e.getMessage());
      return false;
    }
  }

  // ---------------- Internal helpers ----------------

  public String get(String key) {
    try {
      requireInit();

      String ivB64 = store.getProperty(entryIvKey(key));
      String ctB64 = store.getProperty(entryCtKey(key));

      if (ivB64 == null || ctB64 == null) {
        return null; // Caller decides what to do (native method returns false)
      }

      byte[] iv = Base64.getDecoder().decode(ivB64);
      byte[] ct = Base64.getDecoder().decode(ctB64);

      byte[] pt = aesGcmDecrypt(sessionKey, iv, ct);
      return new String(pt, StandardCharsets.UTF_8);
    } catch (Exception e) {
      // Wrong passphrase or tampered store will land here
      ZPECore.log("Security get failed: " + e.getMessage());
      return null;
    }
  }

  public ZPEList listKeys() {
    ZPEList l = new ZPEList();
    try {
      requireInit();

      // Keys are visible by design (can hide later if you want)
      Set<String> names = new HashSet<>();
      for (Object kObj : store.keySet()) {
        String k = String.valueOf(kObj);
        if (k.startsWith("entry.") && k.endsWith(".ct")) {
          String name = k.substring("entry.".length(), k.length() - ".ct".length());
          names.add(name);
        }
      }

      List<String> sorted = new ArrayList<>(names);
      Collections.sort(sorted);

      for (String s : sorted) {
        l.add(new ZPEString(s));
      }

      return l;
    } catch (Exception e) {
      ZPECore.log("Security list_keys failed: " + e.getMessage());
      // return empty list rather than false here; it’s less annoying
      return l;
    }
  }

  private void ensureStorePath() throws Exception {
    if (storePath != null) return;

    // Change this to your ZPE data directory if you have one.
    // This keeps it portable and simple.
    Path base = Paths.get(System.getProperty("user.home"), ".zpe", "secure");
    Files.createDirectories(base);

    storePath = base.resolve("store.properties");
  }

  private void loadStore() throws Exception {
    store.clear();
    try (InputStream in = Files.newInputStream(storePath)) {
      store.load(in);
    }
  }

  private void persistStore() throws Exception {
    try (OutputStream out = Files.newOutputStream(storePath)) {
      store.store(out, "ZPE Secure Store");
    }
  }

  private void requireInit() {
    if (sessionKey == null || salt == null) {
      throw new IllegalStateException("Security not initialised.");
    }
  }

  private void wipeKey() {
    sessionKey = null;
    if (salt != null) Arrays.fill(salt, (byte) 0);
    salt = null;
  }

  private SecretKey deriveKey(String passphrase, byte[] salt, int iterations) throws Exception {
    PBEKeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, iterations, KEY_BITS);
    SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    byte[] keyBytes = skf.generateSecret(spec).getEncoded();
    return new SecretKeySpec(keyBytes, "AES");
  }

  private byte[] aesGcmEncrypt(SecretKey key, byte[] iv, byte[] pt) throws Exception {
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
    return c.doFinal(pt);
  }

  private byte[] aesGcmDecrypt(SecretKey key, byte[] iv, byte[] ct) throws Exception {
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
    // AEADBadTagException (wrong passphrase/tampered data) is thrown here
    return c.doFinal(ct);
  }

  // ---------------- Native method implementations ----------------
  // Uses the same pattern as your MySQL object.

  static class init_Command implements jamiebalfour.zpe.interfaces.ZPEObjectNativeMethod {
    @Override
    public String[] getParameterNames() {
      return new String[]{"passphrase"};
    }

    @Override
    public String[] getParameterTypes() {
      return new String[]{"string"};
    }

    @Override
    public ZPEType MainMethod(JBBinarySearchTree<String, ZPEType> parameters, ZPEObject parent) {
      try {
        String pass = parameters.get("passphrase").toString();
        return new ZPEBoolean(((ZPEVaultObject) parent).init(pass));
      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 3;
    }

    @Override
    public String getName() {
      return "init";
    }
  }

  static class set_Command implements jamiebalfour.zpe.interfaces.ZPEObjectNativeMethod {
    @Override
    public String[] getParameterNames() {
      return new String[]{"key", "value"};
    }

    @Override
    public String[] getParameterTypes() {
      return new String[]{"string", "string"};
    }

    @Override
    public ZPEType MainMethod(JBBinarySearchTree<String, ZPEType> parameters, ZPEObject parent) {
      try {
        String k = parameters.get("key").toString();
        String v = parameters.get("value").toString();
        return new ZPEBoolean(((ZPEVaultObject) parent).set(k, v));
      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 3;
    }

    @Override
    public String getName() {
      return "set";
    }
  }

  static class get_Command implements jamiebalfour.zpe.interfaces.ZPEObjectNativeMethod {
    @Override
    public String[] getParameterNames() {
      return new String[]{"key"};
    }

    @Override
    public String[] getParameterTypes() {
      return new String[]{"string"};
    }

    @Override
    public ZPEType MainMethod(JBBinarySearchTree<String, ZPEType> parameters, ZPEObject parent) {
      try {
        String k = parameters.get("key").toString();
        String val = ((ZPEVaultObject) parent).get(k);
        if (val == null) return new ZPEBoolean(false);
        return new ZPEString(val);
      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 3;
    }

    @Override
    public String getName() {
      return "get";
    }
  }

  static class has_Command implements jamiebalfour.zpe.interfaces.ZPEObjectNativeMethod {
    @Override
    public String[] getParameterNames() {
      return new String[]{"key"};
    }

    @Override
    public String[] getParameterTypes() {
      return new String[]{"string"};
    }

    @Override
    public ZPEType MainMethod(JBBinarySearchTree<String, ZPEType> parameters, ZPEObject parent) {
      try {
        String k = parameters.get("key").toString();
        return new ZPEBoolean(((ZPEVaultObject) parent).has(k));
      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 3;
    }

    @Override
    public String getName() {
      return "has";
    }
  }

  static class delete_Command implements jamiebalfour.zpe.interfaces.ZPEObjectNativeMethod {
    @Override
    public String[] getParameterNames() {
      return new String[]{"key"};
    }

    @Override
    public String[] getParameterTypes() {
      return new String[]{"string"};
    }

    @Override
    public ZPEType MainMethod(JBBinarySearchTree<String, ZPEType> parameters, ZPEObject parent) {
      try {
        String k = parameters.get("key").toString();
        return new ZPEBoolean(((ZPEVaultObject) parent).delete(k));
      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 3;
    }

    @Override
    public String getName() {
      return "delete";
    }
  }

  static class list_keys_Command implements jamiebalfour.zpe.interfaces.ZPEObjectNativeMethod {
    @Override
    public String[] getParameterNames() {
      return new String[]{};
    }

    @Override
    public String[] getParameterTypes() {
      return new String[0];
    }

    @Override
    public ZPEType MainMethod(JBBinarySearchTree<String, ZPEType> parameters, ZPEObject parent) {
      try {
        return ((ZPEVaultObject) parent).listKeys();
      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 3;
    }

    @Override
    public String getName() {
      return "list_keys";
    }
  }

  static class close_Command implements jamiebalfour.zpe.interfaces.ZPEObjectNativeMethod {
    @Override
    public String[] getParameterNames() {
      return new String[]{};
    }

    @Override
    public String[] getParameterTypes() {
      return new String[0];
    }

    @Override
    public ZPEType MainMethod(JBBinarySearchTree<String, ZPEType> parameters, ZPEObject parent) {
      try {
        return new ZPEBoolean(((ZPEVaultObject) parent).close());
      } catch (Exception e) {
        return new ZPEBoolean(false);
      }
    }

    @Override
    public int getRequiredPermissionLevel() {
      return 3;
    }

    @Override
    public String getName() {
      return "close";
    }
  }
}