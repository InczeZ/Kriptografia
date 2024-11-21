package modes;

import Cipher.BlockCipher;

public class CBCMode {
    private final BlockCipher cipher;
    private final int blockSize;

    public CBCMode(BlockCipher cipher, int blockSize) {
        if (blockSize <= 0) {
            throw new IllegalArgumentException("Block size must be greater than 0");
        }
        this.cipher = cipher;
        this.blockSize = blockSize;
    }

    public byte[] encrypt(byte[] plaintext, byte[] iv) throws Exception {
        byte[] ciphertext = new byte[plaintext.length];
        byte[] prevBlock = iv;

        for (int i = 0; i < plaintext.length; i += blockSize) {
            byte[] block = new byte[blockSize];
            System.arraycopy(plaintext, i, block, 0, blockSize);

            for (int j = 0; j < blockSize; j++) {
                block[j] ^= prevBlock[j];
            }

            byte[] encryptedBlock = cipher.encrypt(block, iv);
            System.arraycopy(encryptedBlock, 0, ciphertext, i, blockSize);
            prevBlock = encryptedBlock;
        }
        return ciphertext;
    }

    public byte[] decrypt(byte[] ciphertext, byte[] iv) throws Exception {
        byte[] plaintext = new byte[ciphertext.length];
        byte[] prevBlock = iv;

        for (int i = 0; i < ciphertext.length; i += blockSize) {
            byte[] block = new byte[blockSize];
            System.arraycopy(ciphertext, i, block, 0, blockSize);

            byte[] decryptedBlock = cipher.decrypt(block, iv);
            for (int j = 0; j < blockSize; j++) {
                decryptedBlock[j] ^= prevBlock[j];
            }

            System.arraycopy(decryptedBlock, 0, plaintext, i, blockSize);
            prevBlock = block;
        }
        return plaintext;
    }
}
