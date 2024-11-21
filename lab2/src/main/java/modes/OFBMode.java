package modes;

import Cipher.BlockCipher;

public class OFBMode {
    private final BlockCipher cipher;
    private final int blockSize;

    public OFBMode(BlockCipher cipher, int blockSize) {
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
            feedback = cipher.encrypt(feedback, iv);

            for (int j = 0; j < blockSize && i + j < plaintext.length; j++) {
                ciphertext[i + j] = (byte) (plaintext[i + j] ^ feedback[j]);
            }
        }
        return ciphertext;
    }

    public byte[] decrypt(byte[] ciphertext, byte[] iv) throws Exception {
        return encrypt(ciphertext, iv);
    }
}
