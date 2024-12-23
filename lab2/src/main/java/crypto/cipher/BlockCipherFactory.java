package crypto.cipher;

import java.lang.reflect.InvocationTargetException;
import java.util.Map;
import java.util.HashMap;

public class BlockCipherFactory {
    public static BlockCipher createCipher(String algorithm, byte[] key, String mode) throws DESException {
        Map<String, Class<? extends BlockCipher>> cipherMap = new HashMap<>();
        cipherMap.put("DES", DesCipher.class);
        cipherMap.put("Vigenere", VigenereCipher.class);

        Class<? extends BlockCipher> cipherClass = cipherMap.get(algorithm.toUpperCase());
        if (cipherClass != null) {
            try {
                return cipherClass.getConstructor(byte[].class, String.class).newInstance(key, mode);
            } catch (NoSuchMethodException | InvocationTargetException | InstantiationException |
                     IllegalAccessException exception) {
                throw new DESException("Error creatinng cipher", exception);
            }
        }
        throw new IllegalArgumentException("Unsupported cipher: " + algorithm);
    }
}
