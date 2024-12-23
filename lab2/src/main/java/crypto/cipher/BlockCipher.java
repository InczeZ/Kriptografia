package crypto.cipher;

public interface BlockCipher {
    byte[] encrypt(byte[] plaintext, byte[] iv) throws DESException;
    byte[] decrypt(byte[] ciphertext, byte[] iv) throws DESException;
}
