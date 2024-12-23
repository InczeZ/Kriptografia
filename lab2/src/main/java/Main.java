import client.Client;
import crypto.cipher.CipherNegotiation;
import crypto.cipher.DESException;
import lombok.extern.slf4j.Slf4j;
import message.MyMessage;
import server.KeyServer;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

@Slf4j
public class Main {
    public static void main(String[] args) {
        String serverAddress = "localhost";
        int port = 8000;

        Thread serverThread = new Thread(() -> {
            try {
                KeyServer.main(null);
            } catch (Exception e) {
                System.err.println("Error starting KeyServer: " + e.getMessage());
                log.error("Keyserver error: ", e);
            }
        });

        serverThread.start();

        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        try {
            MyMessage message = new MyMessage();

            Client client1 = new Client("client1", serverAddress, port, message);
            Client client2 = new Client("client2", serverAddress, port, message);

            client1.registerWithServer();
            client2.registerWithServer();

            client2.retrievePeerPublicKey(client1.getClientId());
            client1.retrievePeerPublicKey(client2.getClientId());

            String key1 = client1.generateRandomSecret();
            String key2 = client2.generateRandomSecret();
            String commonSecret = client1.generateCommonSecret(key1, key2);
            System.out.println("Common Secret: " + commonSecret);

            List<String> algorithms = Arrays.asList("DES", "Vigenere");
            List<String> modes = Arrays.asList("CFB", "CTR", "ECB", "OFB");

            List<String> client1Ciphers = CipherNegotiation.generateSupportedCiphers(algorithms, modes);
            List<String> client2Ciphers = CipherNegotiation.generateSupportedCiphers(List.of("DES"), modes);

            String agreedCipher = CipherNegotiation.negotiateCipher(client1Ciphers, client2Ciphers);
            if (agreedCipher == null) {
                log.info("Client did not agree on cipher");
                return;
            }

            log.info("Cipher agreed: {}", agreedCipher);

            client1.setCipher(agreedCipher);
            client2.setCipher(agreedCipher);

            String loremIpsum = message.getMessage();
            int quarterOfLoremIpsum = loremIpsum.length()/4;
            String part1 = loremIpsum.substring(0, quarterOfLoremIpsum);
            String part2 = loremIpsum.substring(quarterOfLoremIpsum, quarterOfLoremIpsum * 2);
            String part3 = loremIpsum.substring(quarterOfLoremIpsum * 2, quarterOfLoremIpsum * 3);
            String part4 = loremIpsum.substring(quarterOfLoremIpsum * 3);

            client1.sendEncryptedMessage(part1, client2);
            client2.sendEncryptedMessage(part2, client1);
            client1.sendEncryptedMessage(part3, client2);
            client2.sendEncryptedMessage(part4, client1);

            String finalMessage = message.getConstructedMessage();
            if (!Objects.equals(finalMessage, message.getMessage())) {
                log.info(finalMessage);
                log.info("Messages are not equal");
            } else {
                log.info("Encryption successful");
            }

            client1.unregisterFromServer();
            client2.unregisterFromServer();

            KeyServer.stopServer();
            Client stopClient = new Client("stopClient", serverAddress, port, null);

            stopClient.registerWithServer();
            serverThread.join();

        } catch (DESException | InterruptedException e) {
            System.err.println("Error: " + e.getMessage());
            log.error(e.getMessage(), e);
        }
    }
}
