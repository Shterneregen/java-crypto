package random.hash;

import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class HashUtilsTest {

	@Test
	public void generateRandomSalt() {
		byte[] salt = HashUtils.generateRandomSalt();
		assertNotNull(salt);
		System.out.println("salt: " + DatatypeConverter.printHexBinary(salt));
	}

	@Test
	public void createSha2Hash() throws Exception {
		byte[] salt = HashUtils.generateRandomSalt();
		String valueToHash = UUID.randomUUID().toString();
		byte[] hash = HashUtils.createSha2Hash(valueToHash, salt);
		assertNotNull(hash);
		byte[] hash2 = HashUtils.createSha2Hash(valueToHash, salt);
		assertEquals(DatatypeConverter.printHexBinary(hash), DatatypeConverter.printHexBinary(hash2));
	}

	@Test
	public void testHashPassword() {
		String password = "Good Password";
		String passwordHash = HashUtils.hashPassword(password);
		System.out.println("testHashPassword: " + passwordHash);
		assertTrue(HashUtils.verifyPassword(password, passwordHash));
	}

	@Test
	public void testSimpleHash() {
		String password = "Good Password";
		String passwordHash = HashUtils.simpleHash(password);
		System.out.println("testSimpleHash: " + passwordHash);
	}

}
