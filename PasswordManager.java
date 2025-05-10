import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;

public class PasswordManager {
  private static final String KEY_FILE = "secure_aes.txt";
  private static final String DB_FILE = "passwords.txt";
  private static final int SALT_LEN = 16;
  private static final int IV_LEN = 16;
  private static final int AES_KEY_SZ = 256;

  private static Map < String, String > passwordStore = new HashMap < > ();

  public static void main(String[] args) throws Exception {
  
    if (!isRoot()) {
      System.err.println("Error: Must be run as root.");
      return;
    }

    loadDatabase();

    Console console = System.console();
    if (console == null) {
      System.err.println("Run from terminal.");
      return;
    }

    while (true) {
      System.out.print("\n[1] Add  [2] Remove  [3] Update  [4] Get  [5] Get-All  [6] Exit : ");
      String choice = console.readLine().trim();
      switch (choice) {
      case "1":
        add(console);
        break;
      case "2":
        remove(console);
        break;
      case "3":
        update(console);
        break;
      case "4":
        get(console);
        break;
      case "5":
        listEntries();
        break;
      case "6":
        saveDatabase();
        System.out.println("Goodbye.");
        return;
      default:
        System.out.println("Invalid option.");
      }
    }
  }

  private static void add(Console console) throws Exception {
    char[] masterPw = console.readPassword("Master password: ");
    SecretKey aesKey = loadAESKey(masterPw);

    String user = console.readLine("Username: ");
    String url = console.readLine("URL: ");
    String pass = generateStrongPassword();

    String encrypted = encrypt(pass, aesKey);
    passwordStore.put(user + ":" + url, encrypted);
    saveDatabase();
    System.out.println("Entry added.");

    zeroOut(masterPw);
  }

  private static void remove(Console console) throws Exception {
    String user = console.readLine("Username: ");
    String url = console.readLine("URL: ");
    String key = user + ":" + url;
    if (passwordStore.remove(key) != null) {
      saveDatabase();
      System.out.println("Entry removed.");
    } else {
      System.out.println("No such entry.");
    }
  }

  private static void update(Console console) throws Exception {
    char[] masterPw = console.readPassword("Master password: ");
    SecretKey aesKey = loadAESKey(masterPw);

    String user = console.readLine("Username: ");
    String url = console.readLine("URL: ");
    String newPass = generateStrongPassword();

    String encrypted = encrypt(newPass, aesKey);
    passwordStore.put(user + ":" + url, encrypted);
    saveDatabase();
    System.out.println("Entry updated.");

    zeroOut(masterPw);
  }

  private static void get(Console console) throws Exception {
    char[] masterPw = console.readPassword("Master password: ");
    SecretKey aesKey = loadAESKey(masterPw);

    String user = console.readLine("Username: ");
    String url = console.readLine("URL: ");
    String encrypted = passwordStore.get(user + ":" + url);
    if (encrypted != null) {
      String decrypted = decrypt(encrypted, aesKey);
      System.out.println("Password: " + decrypted);
    } else {
      System.out.println("No such entry.");
    }

    zeroOut(masterPw);
  }

  private static SecretKey loadAESKey(char[] password) throws Exception {
    byte[] fileData = Files.readAllBytes(Paths.get(KEY_FILE));
    byte[] salt = Arrays.copyOfRange(fileData, 0, SALT_LEN);
    byte[] iv = Arrays.copyOfRange(fileData, SALT_LEN, SALT_LEN + IV_LEN);
    byte[] encKey = Arrays.copyOfRange(fileData, SALT_LEN + IV_LEN, fileData.length);

    PBEKeySpec spec = new PBEKeySpec(password, salt, 65536, AES_KEY_SZ);
    SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    byte[] derivedBytes = f.generateSecret(spec).getEncoded();
    SecretKey derivedKey = new SecretKeySpec(derivedBytes, "AES");

    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, derivedKey, new IvParameterSpec(iv));
    byte[] aesKeyBytes = cipher.doFinal(encKey);

    zeroOut(derivedBytes);
    return new SecretKeySpec(aesKeyBytes, "AES");
  }

  private static String encrypt(String plain, SecretKey key) throws Exception {
    byte[] iv = SecureRandom.getInstanceStrong().generateSeed(IV_LEN);
    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
    byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
    byte[] combined = new byte[IV_LEN + ct.length];
    System.arraycopy(iv, 0, combined, 0, IV_LEN);
    System.arraycopy(ct, 0, combined, IV_LEN, ct.length);
    return Base64.getEncoder().encodeToString(combined);
  }

  private static String decrypt(String b64, SecretKey key) throws Exception {
    byte[] combined = Base64.getDecoder().decode(b64);
    byte[] iv = Arrays.copyOfRange(combined, 0, IV_LEN);
    byte[] ct = Arrays.copyOfRange(combined, IV_LEN, combined.length);
    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
    byte[] pt = c.doFinal(ct);
    return new String(pt, StandardCharsets.UTF_8);
  }

  private static void loadDatabase() throws IOException {
    Path path = Paths.get(DB_FILE);
    if (!Files.exists(path)) {
      Files.createFile(path);
      return;
    }

    for (String line: Files.readAllLines(path, StandardCharsets.UTF_8)) {
      String[] parts = line.split(":", 3);
      if (parts.length == 3) {
        passwordStore.put(parts[0] + ":" + parts[1], parts[2]);
      }
    }

  }

  private static void saveDatabase() throws IOException {
    try (BufferedWriter w = Files.newBufferedWriter(Paths.get(DB_FILE), StandardCharsets.UTF_8)) {
      for (Map.Entry < String, String > e: passwordStore.entrySet()) {
        String[] keyParts = e.getKey().split(":", 2);
        w.write(keyParts[0] + ":" + keyParts[1] + ":" + e.getValue());
        w.newLine();
      }
    }
  }

  private static String generateStrongPassword() {
    SecureRandom base = new SecureRandom();
    byte[] seed = new byte[16];
    base.nextBytes(seed);
    SecureRandom rnd = new SecureRandom(seed);

    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < 30; i++) {
      int v = Math.floorMod(rnd.nextInt(), 128);
      if (v < 32) v += 33;
      sb.append((char) v);
    }
    return sb.toString();
  }
  private static void listEntries() {
    if (passwordStore.isEmpty()) {
        System.out.println("No entries found.");
        return;
    }

    System.out.println("Saved entries:");
    for (String key : passwordStore.keySet()) {
        System.out.println(" - " + key); 
    }
  }

  private static void zeroOut(byte[] b) {
    if (b != null) Arrays.fill(b, (byte) 0);
  }
  
  private static void zeroOut(char[] c) {
    if (c != null) Arrays.fill(c, '\0');
  }
  
  private static boolean isRoot() {
    return "root".equals(System.getProperty("user.name"));
  }
}
