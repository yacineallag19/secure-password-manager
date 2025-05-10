import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

public class InitialiseDatabase {
  private static final String KEY_FILE = "secure_aes.txt";
  private static final int AES_KEY_SIZE = 256;
  private static final int SALT_LEN = 16;
  private static final int IV_LEN = 16;

  public static void main(String[] args) throws Exception {
    if (!isRoot()) {
      System.err.println("Error: Must be run as root.");
      return;
    }

    Console console = System.console();
    if (console == null) {
      System.err.println("Run from terminal.");
      return;
    }

    char[] password = console.readPassword("Enter master password to protect AES key: ");

    SecretKey aesKey = generateAESKey();

    byte[] salt = SecureRandom.getInstanceStrong().generateSeed(SALT_LEN);
    SecretKey derivedKey = deriveKeyFromPassword(password, salt);

    byte[] iv = SecureRandom.getInstanceStrong().generateSeed(IV_LEN);
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, derivedKey, new IvParameterSpec(iv));
    byte[] encryptedAesKey = cipher.doFinal(aesKey.getEncoded());

    try (FileOutputStream fos = new FileOutputStream(KEY_FILE)) {
      fos.write(salt);
      fos.write(iv);
      fos.write(encryptedAesKey);
    }

    Runtime.getRuntime().exec(new String[] {
      "chmod",
      "600",
      KEY_FILE
    }).waitFor();

    zeroOut(password);
    zeroOut(aesKey.getEncoded());
    zeroOut(derivedKey.getEncoded());

    System.out.println("Key initialized and stored securely.");
  }

  private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(AES_KEY_SIZE);
    return keyGen.generateKey();
  }

  private static SecretKey deriveKeyFromPassword(char[] password, byte[] salt) throws Exception {
    PBEKeySpec spec = new PBEKeySpec(password, salt, 65536, AES_KEY_SIZE);
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    byte[] keyBytes = factory.generateSecret(spec).getEncoded();
    return new SecretKeySpec(keyBytes, "AES");
  }

  private static void zeroOut(byte[] array) {
    if (array != null) Arrays.fill(array, (byte) 0);
  }

  private static void zeroOut(char[] array) {
    if (array != null) Arrays.fill(array, '\0');
  }

  private static boolean isRoot() {
    return "root".equals(System.getProperty("user.name"));
  }
}
