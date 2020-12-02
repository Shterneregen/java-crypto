package random.hash;

import org.apache.commons.codec.binary.Hex;
import org.mindrot.jbcrypt.BCrypt;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

public class HashUtils {

	private static final Logger LOG = Logger.getLogger(HashUtils.class.getName());

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

	public static String simpleHash(String data) {
		try {
			MessageDigest md = MessageDigest.getInstance(SHA_ALGORITHM);
			byte[] encodedHash = md.digest(data.getBytes(StandardCharsets.UTF_8));
			return new String(Hex.encodeHex(encodedHash));
		} catch (NoSuchAlgorithmException e) {
			LOG.log(Level.SEVERE, e.getMessage(), e);
			return "";
		}
	}
}
