import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.InputStream;
import java.util.Arrays;

@Getter
@Slf4j
public class CipherConfig {
    private final int blockSize;
    private final String algorithm;
    private final byte[] key;
    private final String mode;
    private byte[] iv;

    public CipherConfig(String filePath) throws Exception {
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(filePath)) {
            if (inputStream == null) {
                throw new IllegalArgumentException("File not found in resources: " + filePath);
            }

            ObjectMapper objectMapper = new ObjectMapper();
            CipherConfigData configData = objectMapper.readValue(inputStream, CipherConfigData.class);

            this.blockSize = configData.getBlockSize();
            this.algorithm = configData.getAlgorithm();
            this.key = hexStringToByteArray(configData.getKey());
            this.mode = configData.getMode();
            if (configData.getIv() != null) {
                this.iv = hexStringToByteArray(configData.getIv());
            }
        } catch (Exception ex) {
            log.error("Failed to load JSON configuration file", ex);
            throw ex;
        }
    }


    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    @Override
    public String toString() {
        return "CipherConfig {\n" +
                "\tblockSize=" + blockSize + ",\n" +
                "\talgorithm='" + algorithm + "',\n" +
                "\tkey=" + Arrays.toString(key) + ",\n" +
                "\tmode='" + mode + "',\n" +
                "\tiv=" + Arrays.toString(iv) + ",\n" +
                '}';
    }



}
