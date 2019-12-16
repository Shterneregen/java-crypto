package random.hash;

import org.mindrot.jbcrypt.BCrypt;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class HashUtils {

    private static final String SHA_ALGORITHM = "SHA-256";

    private HashUtils() {
    }

    public static byte[] generateRandomSalt() {
        byte[] salt = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(salt);
        return salt;
    }

    public static byte[] createSha2Hash(String input, byte[] salt) throws Exception {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        byteStream.write(salt);
        byteStream.write(input.getBytes());
        byte[] valueToHash = byteStream.toByteArray();
        MessageDigest messageDigest = MessageDigest.getInstance(SHA_ALGORITHM);
        return messageDigest.digest(valueToHash);
    }

    public static String hashPassword(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt());
    }

    public static boolean verifyPassword(String password, String hashedPassword) {
        return BCrypt.checkpw(password, hashedPassword);
    }

}
