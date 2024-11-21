package Cipher;

public interface BlockCipher {
    byte[] encrypt(byte[] plaintext, byte[] iv) throws Exception;
    byte[] decrypt(byte[] ciphertext, byte[] iv) throws Exception;
}
