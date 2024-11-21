package modes;

import Cipher.BlockCipher;

public class ECBMode {
    private final BlockCipher cipher;
    private final int blockSize;

    public ECBMode(BlockCipher cipher, int blockSize) {
        if (blockSize <= 0) {
            throw new IllegalArgumentException("Block size must be greater than 0");
        }
        this.cipher = cipher;
        this.blockSize = blockSize;
    }

    public byte[] encrypt(byte[] plaintext) throws Exception {
        int paddedLength = (int) Math.ceil((double) plaintext.length / blockSize) * blockSize;
        byte[] ciphertext = new byte[paddedLength];

        for (int i = 0; i < plaintext.length; i += blockSize) {
            byte[] block = new byte[blockSize];
            int remaining = Math.min(blockSize, plaintext.length - i);
            System.arraycopy(plaintext, i, block, 0, remaining);

            byte[] encryptedBlock = cipher.encrypt(block, null);
            System.arraycopy(encryptedBlock, 0, ciphertext, i, blockSize);
        }
        return ciphertext;
    }

    public byte[] decrypt(byte[] ciphertext) throws Exception {
        byte[] plaintext = new byte[ciphertext.length];

        for (int i = 0; i < ciphertext.length; i += blockSize) {
            byte[] block = new byte[blockSize];
            System.arraycopy(ciphertext, i, block, 0, blockSize);

            byte[] decryptedBlock = cipher.decrypt(block, null);
            System.arraycopy(decryptedBlock, 0, plaintext, i, blockSize);
        }
        return plaintext;
    }
}
