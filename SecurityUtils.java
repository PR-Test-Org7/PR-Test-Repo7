import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;

/**
 * INTENTIONALLY VULNERABLE - FOR TESTING ONLY
 */
public class SecurityUtils {

    // VULNERABILITY: Hardcoded Encryption Key (Critical)
    private static final byte[] ENCRYPTION_KEY = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };

    private static final String JWT_SECRET = "my-super-secret-key-12345";

    // VULNERABILITY: Weak Cryptography - DES (High)
    public byte[] encryptData(String data) throws Exception {
        // Using deprecated DES algorithm
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(ENCRYPTION_KEY, "DES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        return cipher.doFinal(data.getBytes());
    }

    // VULNERABILITY: Weak Cryptography - MD5 Hash (High)
    public String hashPassword(String password) throws NoSuchAlgorithmException {
        // MD5 is cryptographically broken
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());

        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    // VULNERABILITY: Weak Cryptography - SHA1 (High)
    public String signDocument(String document) throws NoSuchAlgorithmException {
        // SHA-1 is deprecated and vulnerable
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] signature = sha1.digest(document.getBytes());

        return Base64.getEncoder().encodeToString(signature);
    }

    // VULNERABILITY: Insecure Random Number Generation (High)
    public String generateToken() {
        // Using predictable Random instead of SecureRandom
        Random random = new Random(System.currentTimeMillis());
        byte[] tokenBytes = new byte[16];
        random.nextBytes(tokenBytes);

        return Base64.getEncoder().encodeToString(tokenBytes);
    }

    // VULNERABILITY: Insecure Random for sensitive operations (High)
    public String generateResetToken(String userId) {
        // Predictable token generation
        Random rand = new Random();
        long token = rand.nextLong();
        return userId + "_" + Long.toHexString(token);
    }

    // VULNERABILITY: Weak Cryptography - ECB mode (High)
    public byte[] encryptSensitiveData(String data, SecretKey key) throws Exception {
        // ECB mode doesn't provide semantic security
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(data.getBytes());
    }

    // VULNERABILITY: Insecure Random in UUID generation (Medium/High)
    public String generateUserId() {
        // Using time-based seed makes it predictable
        Random random = new Random();
        return "USER_" + random.nextInt(1000000);
    }
}
