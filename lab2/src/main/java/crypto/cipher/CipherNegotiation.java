package crypto.cipher;

import java.util.List;

public class CipherNegotiation {

    public static String negotiateCipher(List<String> client1Ciphers, List<String> client2Ciphers) {
        for (String cipher : client1Ciphers) {
            if (client2Ciphers.contains(cipher)) {
                return cipher;
            }
        }
        return null;
    }

    public static List<String> generateSupportedCiphers(List<String> algorithms, List<String> modes) {
        return algorithms.stream()
                .flatMap(algorithm -> modes.stream().map(mode -> algorithm + "/" + mode))
                .toList();
    }
}
