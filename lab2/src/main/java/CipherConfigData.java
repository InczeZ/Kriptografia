import lombok.Getter;

@Getter
public class CipherConfigData {
    // Getters and setters
    private int blockSize;
    private String algorithm;
    private String key;
    private String mode;
    private String iv;
    private String padding;

}