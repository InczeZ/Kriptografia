package crypto.cipher;

public class VigenereCipher implements BlockCipher {
    private final String key;

    public VigenereCipher(String key) {
        this.key = key;
    }

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] iv) {
        byte[] ciphertext = new byte[plaintext.length];
        for (int i = 0; i < plaintext.length; i++) {
            ciphertext[i] = (byte) ((plaintext[i] + key.charAt(i % key.length())) % 256);
        }
        return ciphertext;
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] iv) {
        byte[] plaintext = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i++) {
            plaintext[i] = (byte) ((ciphertext[i] - key.charAt(i % key.length()) + 256) % 256);
        }
        return plaintext;
    }
}
