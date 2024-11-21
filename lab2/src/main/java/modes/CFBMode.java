package modes;

import Cipher.BlockCipher;

public class CFBMode {
    private final BlockCipher cipher;
    private final int blockSize;

    public CFBMode(BlockCipher cipher, int blockSize) {
        if (blockSize <= 0) {
            throw new IllegalArgumentException("Block size must be greater than 0");
        }
        this.cipher = cipher;
        this.blockSize = blockSize;
    }

    public byte[] encrypt(byte[] plaintext, byte[] iv) throws Exception {
        byte[] ciphertext = new byte[plaintext.length];
        byte[] feedback = iv.clone();

        for (int i = 0; i < plaintext.length; i += blockSize) {
            byte[] encryptedFeedback = cipher.encrypt(feedback, iv);

            for (int j = 0; j < blockSize && i + j < plaintext.length; j++) {
                ciphertext[i + j] = (byte) (plaintext[i + j] ^ encryptedFeedback[j]);
            }

            System.arraycopy(ciphertext, i, feedback, 0, blockSize);
        }
        return ciphertext;
    }

    public byte[] decrypt(byte[] ciphertext, byte[] iv) throws Exception {
        byte[] plaintext = new byte[ciphertext.length];
        byte[] feedback = iv.clone();

        for (int i = 0; i < ciphertext.length; i += blockSize) {
            byte[] encryptedFeedback = cipher.encrypt(feedback, iv);

            for (int j = 0; j < blockSize && i + j < ciphertext.length; j++) {
                plaintext[i + j] = (byte) (ciphertext[i + j] ^ encryptedFeedback[j]);
            }

            System.arraycopy(ciphertext, i, feedback, 0, blockSize);
        }
        return plaintext;
    }
}
