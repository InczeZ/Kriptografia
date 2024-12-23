package crypto.cipher;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class DesCipher implements BlockCipher {
    private final SecretKeySpec keySpec;
    private final String mode;

    public DesCipher(byte[] key, String mode) {
        this.keySpec = new SecretKeySpec(key, "DES");
        this.mode = mode;
    }

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] iv) throws DESException {
        try {
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
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException |
                 InvalidAlgorithmParameterException | BadPaddingException | InvalidKeyException exception) {
            throw new DESException("DES encryption error", exception);
        }
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] iv) throws DESException {
        try {
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
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 InvalidAlgorithmParameterException | BadPaddingException exception) {
            throw new DESException("DES decryption error", exception);
        }
    }
}
