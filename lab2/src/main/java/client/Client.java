package client;

import crypto.cipher.BlockCipher;
import crypto.cipher.BlockCipherFactory;
import crypto.cipher.DESException;
import message.MyMessage;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Base64;

@Slf4j
public class Client {
    @Getter
    private final String clientId;
    private final String serverAddress;
    private final int serverPort;
    private PublicKey publicKey;
    private BlockCipher cipher;
    private final byte[] key = new byte[8];
    private final byte[] iv = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    private final MyMessage message;

    public Client(String clientId, String serverAddress, int serverPort, MyMessage message) {
        this.clientId = clientId;
        this.serverAddress = serverAddress;
        this.serverPort = serverPort;
        this.message = message;
        generateKeyPair();
    }

    private void generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPair = keyGen.generateKeyPair();
            this.publicKey = keyPair.getPublic();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error generating key pair: " + e.getMessage());
        }
    }

    public void registerWithServer() {
        try (Socket socket = new Socket(serverAddress, serverPort);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {
            out.writeObject("register");
            out.writeObject(clientId);
            out.writeObject(publicKey);

            String response = (String) in.readObject();
            log.info("Server response: {}", response);
        } catch (IOException | ClassNotFoundException e) {
            log.info("Error registering with server: {}", e.getMessage());
        }
    }

    public void unregisterFromServer() {
        try (Socket socket = new Socket(serverAddress, serverPort);
                 ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                 ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {
            if (!socket.isClosed()) {
                out.writeObject("unregister");
                out.writeObject(clientId);
                out.flush();
                log.info("{} has unregistered from the server.", clientId);
                out.close();
                in.close();
                socket.close();
                log.info("{} has successfully disconnected.", clientId);
            }
        } catch (IOException e) {
            log.error("Error unregistering {} from server: {}", clientId, e.getMessage(), e);
        }
    }

    public void retrievePeerPublicKey(String peerId) {
        try (Socket socket = new Socket(serverAddress, serverPort);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            out.writeObject("getPublicKey");
            out.writeObject(peerId);

            log.info("Retrieved public key for {}", peerId);
        } catch (IOException e) {
            log.error("Error retrieving public key: {}", e.getMessage());
        }
    }

    public void sendEncryptedMessage(String message, Client recipient) throws DESException {
        if (cipher == null) {
            throw new IllegalStateException("Cipher not initialized.");
        }
        byte[] encrypted = cipher.encrypt(message.getBytes(), iv);
        log.info("{} sent encrypted message: {}", clientId, Base64.getEncoder().encodeToString(encrypted));
        recipient.receiveEncryptedMessage(encrypted);
    }

    public void receiveEncryptedMessage(byte[] encryptedMessage) throws DESException {
        if (cipher == null) {
            throw new IllegalStateException("Cipher not initialized.");
        }
        byte[] decrypted = cipher.decrypt(encryptedMessage, iv);
        message.constructMessage(new String(decrypted));
        log.info("{} received decrypted message: {}", clientId, new String(decrypted));
    }

    public String generateRandomSecret() {
        byte[] randomBytes = new byte[16];
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getEncoder().encodeToString(randomBytes);
    }

    public void setCipher(String agreedCipher) throws DESException {
        String[] parts = agreedCipher.split("/");
        String algorithm = parts[0];
        String mode = parts[1];
        this.cipher = BlockCipherFactory.createCipher(algorithm, key, mode);
        log.info("{} initialized cipher: {}", clientId, agreedCipher);
    }

    public String generateCommonSecret(String key1, String key2) {
        return Base64.getEncoder().encodeToString((key1 + key2).getBytes());
    }
}
