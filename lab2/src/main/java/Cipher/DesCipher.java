package Cipher;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class DesCipher implements BlockCipher {
    private final SecretKeySpec keySpec;
    private final String mode;

    public DesCipher(byte[] key, String mode) {
        this.keySpec = new SecretKeySpec(key, "DES");
        this.mode = mode;
    }

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/" + mode + "/NoPadding");

        if (iv == null) {
            if ("ECB".equalsIgnoreCase(mode)) {
                cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            } else {
                throw new IllegalArgumentException("IV cannot be null for mode: " + mode);
            }
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
        }
        return cipher.doFinal(plaintext);
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/" + mode + "/NoPadding");

        if (iv == null) {
            if ("ECB".equalsIgnoreCase(mode)) {
                cipher.init(Cipher.DECRYPT_MODE, keySpec);
            } else {
                throw new IllegalArgumentException("IV cannot be null for mode: " + mode);
            }
        } else {
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
        }

        return cipher.doFinal(ciphertext);
    }
}
