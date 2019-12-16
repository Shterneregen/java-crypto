package random.symmetric;

import org.junit.Test;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class SymmetricEncryptionUtilsTest {

    @Test
    public void createAesKey() throws NoSuchAlgorithmException {
        SecretKey secretKey = SymmetricEncryptionUtils.createAesKey();
        assertNotNull(secretKey);
        System.out.println(DatatypeConverter.printHexBinary(secretKey.getEncoded()));
    }

    @Test
    public void testCryptoRoutine() throws Exception {
        SecretKey secretKey = SymmetricEncryptionUtils.createAesKey();
        byte[] initVector = SymmetricEncryptionUtils.createInitVector();
        String plainText = "Text to encrypt";
        byte[] cipherText = SymmetricEncryptionUtils.encrypt(plainText, secretKey, initVector);
        assertNotNull(cipherText);
        System.out.println(DatatypeConverter.printHexBinary(cipherText));
        String decryptedText = SymmetricEncryptionUtils.decrypt(cipherText, secretKey, initVector);
        assertEquals(plainText, decryptedText);
    }

}
