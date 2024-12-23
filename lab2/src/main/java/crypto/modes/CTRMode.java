package crypto.modes;

import crypto.cipher.BlockCipher;

public class CTRMode {
    private final BlockCipher cipher;
    private final int blockSize;

    public CTRMode(BlockCipher cipher, int blockSize) {
        if (blockSize <= 0) {
            throw new IllegalArgumentException("Block size must be greater than 0");
        }
        this.cipher = cipher;
        this.blockSize = blockSize;
    }

    public byte[] encrypt(byte[] plaintext, byte[] iv) throws Exception {
        byte[] ciphertext = new byte[plaintext.length];
        byte[] counter = iv.clone();

        for (int i = 0; i < plaintext.length; i += blockSize) {
            byte[] encryptedCounter = cipher.encrypt(counter, iv);

            for (int j = 0; j < blockSize && i + j < plaintext.length; j++) {
                ciphertext[i + j] = (byte) (plaintext[i + j] ^ encryptedCounter[j]);
            }

            incrementCounter(counter);
        }
        return ciphertext;
    }

    public byte[] decrypt(byte[] ciphertext, byte[] iv) throws Exception {
        return encrypt(ciphertext, iv);
    }

    private void incrementCounter(byte[] counter) {
        for (int i = counter.length - 1; i >= 0; i--) {
            if (++counter[i] != 0) break;
        }
    }
}
