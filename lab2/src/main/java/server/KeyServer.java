package server;

import lombok.extern.slf4j.Slf4j;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class KeyServer {
    private static final int PORT = 8000;
    private static volatile boolean stopRequested = false;
    private static final ConcurrentHashMap<String, PublicKey> keyStore = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            log.info("KeyServer is running on port " + PORT);

            while (!stopRequested) {
                Socket clientSocket = serverSocket.accept();
                new Thread(new ClientHandler(clientSocket)).start();
            }

            log.info("KeyServer stopped");
        } catch (IOException e) {
            log.error("KeyServer error: {}", e.getMessage());
        }
    }

    public static void stopServer() {
        stopRequested = true;
    }

    private record ClientHandler(Socket socket) implements Runnable {

        @Override
            public void run() {
                try (ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
                     ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream())) {

                    String command = (String) in.readObject();
                    if ("register".equalsIgnoreCase(command)) {
                        String clientId = (String) in.readObject();
                        PublicKey publicKey = (PublicKey) in.readObject();
                        keyStore.put(clientId, publicKey);
                        out.writeObject("Registration successful for " + clientId);
                    } else if ("getPublicKey".equalsIgnoreCase(command)) {
                        String clientId = (String) in.readObject();
                        PublicKey publicKey = keyStore.get(clientId);
                        out.writeObject(publicKey);
                    } else {
                        out.writeObject("Invalid command");
                    }
                } catch (IOException | ClassNotFoundException e) {
                    log.error("Client handling error: {}", e.getMessage());
                }
            }
        }
}