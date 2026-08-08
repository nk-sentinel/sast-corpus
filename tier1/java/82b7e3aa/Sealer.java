package app;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Sealer {
    static byte[] seal(byte[] key, byte[] value) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
        return cipher.doFinal(value);
    }
}
