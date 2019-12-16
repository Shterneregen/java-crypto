package random.asymmetric;

import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.security.KeyPair;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class AsymmetricEncryptionUtilsTest {

    @Test
    public void generateRsaKeyPair() throws Exception {
        KeyPair keyPair = AsymmetricEncryptionUtils.generateRsaKeyPair();
        assertNotNull(keyPair);
        System.out.println("Private key: " + DatatypeConverter.printHexBinary(keyPair.getPrivate().getEncoded()));
        System.out.println("Public key:  " + DatatypeConverter.printHexBinary(keyPair.getPublic().getEncoded()));
    }

    @Test
    public void testRsaCryptoRoutine() throws Exception {
        KeyPair keyPair = AsymmetricEncryptionUtils.generateRsaKeyPair();
        String plainText = "Text to encrypt";
        byte[] cipherText = AsymmetricEncryptionUtils.encrypt(plainText, keyPair.getPrivate());
        assertNotNull(cipherText);
        System.out.println(DatatypeConverter.printHexBinary(cipherText));
        String decryptedText = AsymmetricEncryptionUtils.decrypt(cipherText, keyPair.getPublic());
        assertEquals(plainText, decryptedText);
    }

}
