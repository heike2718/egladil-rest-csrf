package de.egladil.web.egladil_secure_tokens;

import java.security.SecureRandom;
import java.util.HexFormat;

/**
 *
 */
public class SecureRandomGenerator {

    private static final HexFormat HEX_FORMAT = HexFormat.of();

    private final SecureRandom secureRandom;

    public SecureRandomGenerator() {
        secureRandom = new SecureRandom();
    }

    public SecureRandomGenerator(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    /**
     * @param numberOfBytes int. Must be ≥32 for cryptographic security (generates byteLength*2 hex chars).
     * @throws IllegalArgumentException if byteLength < 32
     */
    public String generateSecureRandomHex(int numberOfBytes) {

        if (numberOfBytes < 32) {
            throw new IllegalArgumentException("minimum numberOfBytes is 32");
        }

        byte[] randomValue = new byte[numberOfBytes];
        secureRandom.nextBytes(randomValue);
        return HEX_FORMAT.formatHex(randomValue);
    }

    /**
     * Generiert ein secure random der Länge 512 bit und gibt es als hex-String zurück.
     *
     * @return String
     */
    public String generateSecureRandomHex() {

        return this.generateSecureRandomHex(64);
    }
}
