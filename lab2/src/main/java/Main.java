import Cipher.BlockCipher;
import Cipher.DesCipher;
import Cipher.VigenereCipher;
import lombok.extern.slf4j.Slf4j;
import modes.*;

import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

@Slf4j
public class Main {
    public static void main(String[] args) {
        String FILE_PATH = "config.json";
        CipherConfig config;
        try {
            config = new CipherConfig(FILE_PATH);
            System.out.println(config);
        } catch (Exception e) {
            log.error("Failed to load config file", e);
            return;
        }

        String inputFilePath = "src/main/resources/sample.png";
        byte[] plaintext;
        try {
            plaintext = Files.readAllBytes(Paths.get(inputFilePath));
            System.out.println("Original file size: " + plaintext.length + " bytes");
        } catch (Exception e) {
            log.error("Failed to read input file", e);
            return;
        }

        BlockCipher cipher;
        byte[] iv = config.getIv();
        try {
            if ("Vigenere".equals(config.getAlgorithm())) {
                cipher = new VigenereCipher(new String(config.getKey()));
            } else if ("DES".equals(config.getAlgorithm())) {
                cipher = new DesCipher(config.getKey(), config.getMode());
            } else {
                log.error("Wrong algorithm name");
                return;
            }
        } catch (Exception e) {
            log.error("Failed to initialize cipher: {}", e.getMessage(), e);
            return;
        }

        byte[] ciphertext;
        byte[] decryptedData;
        int blockSize = config.getBlockSize();

        try {
            switch (config.getMode()) {
                case "ECB":
                    ECBMode ecb = new ECBMode(cipher, blockSize);
                    ciphertext = ecb.encrypt(plaintext);
                    decryptedData = ecb.decrypt(ciphertext);
                    break;

                case "CBC":
                    CBCMode cbc = new CBCMode(cipher, blockSize);
                    ciphertext = cbc.encrypt(plaintext, iv);
                    decryptedData = cbc.decrypt(ciphertext, iv);
                    break;

                case "CFB":
                    CFBMode cfb = new CFBMode(cipher, blockSize);
                    ciphertext = cfb.encrypt(plaintext, iv);
                    decryptedData = cfb.decrypt(ciphertext, iv);
                    break;

                case "OFB":
                    OFBMode ofb = new OFBMode(cipher, blockSize);
                    ciphertext = ofb.encrypt(plaintext, iv);
                    decryptedData = ofb.decrypt(ciphertext, iv);
                    break;

                case "CTR":
                    CTRMode ctr = new CTRMode(cipher, blockSize);
                    ciphertext = ctr.encrypt(plaintext, iv);
                    decryptedData = ctr.decrypt(ciphertext, iv);
                    break;

                default:
                    log.error("Unsupported mode: {}", config.getMode());
                    return;
            }

            String outputFilePath = "src/main/resources/decrypted_output.png";
            try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
                fos.write(decryptedData);
            }

            System.out.println("Decrypted file saved as: " + outputFilePath);

            if (Files.mismatch(Paths.get(inputFilePath), Paths.get(outputFilePath)) == -1) {
                System.out.println("Decryption successful! The files match.");
            } else {
                System.out.println("Decryption failed! The files do not match.");
            }

        } catch (Exception ex) {
            log.error("Encryption/Decryption failed: {}", ex.getMessage(), ex);
        }
    }
}
