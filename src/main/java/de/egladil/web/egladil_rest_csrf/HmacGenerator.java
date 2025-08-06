package de.egladil.web.egladil_rest_csrf;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

class HmacGenerator {


    private static final HexFormat HEX_FORMAT = HexFormat.of();

    private static final Logger LOGGER = LoggerFactory.getLogger(HmacGenerator.class);

    public static final String HMAC_ALGORITHM = "HmacSHA256";

    /**
     * signes the messagePayload with the secretKey and returns it as hex encoded String.
     *
     * @param messagePayload String. The message that is going to be signed. Must not be null.
     * @param secretKey byte[]. The secret. The length of the Array must be 64.
     * @return String
     */
    public String generateHmac(String messagePayload, byte[] secretKey) {
        return this.generateHmac(messagePayload, HMAC_ALGORITHM, secretKey);
    }

    /**
     * signes the messagePayload with the secretKey and returns it as hex encoded String.
     *
     * @param messagePayload String. The message that is going to be signed. Must not be null.
     * @param hmacAlgorithm String. The name of the algorithm. Please use 'HmacSHA256'. For testing purposes it
     *                      is passed as parameter here.
     * @param secretKey byte[]. The secret. The length of the Array must be 64.
     * @return String
     */
    String generateHmac(String messagePayload, String hmacAlgorithm, byte[] secretKey) {

        if (messagePayload == null) {
            throw new IllegalArgumentException("messagePayload must not be null");
        }

        if (hmacAlgorithm == null) {
            throw new IllegalArgumentException("hamacAlgorithm must not be null");
        }

        if (secretKey == null) {
            throw new IllegalArgumentException("secretKey must not be null");
        }

        if (secretKey.length != 64) {
            throw new IllegalArgumentException("Key must be exactly 64 bytes (512 bits) for optimal security");
        }

        try {
            // Generate HMAC
            Mac hmac = Mac.getInstance(hmacAlgorithm);
            hmac.init(new SecretKeySpec(secretKey, hmacAlgorithm));
            byte[] hmacBytes = hmac.doFinal(messagePayload.getBytes());

            return HEX_FORMAT.formatHex(hmacBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            LOGGER.error("Failed to generate hmac: {}", e.getMessage());
            throw new SecurityException("Failed to generate hmac", e);
        }
    }

    /**
     * The messagePayload that is going to be hashed.
     * @param salt String. the salt that ist used for the token
     * @param randomValueHex String. the random string of the token
     * @return String
     */
    String getHmacMessagePayload(String salt, String randomValueHex) {

        return salt.length() + "!" + salt + "!" + randomValueHex.length() + "!" +
                HEX_FORMAT.formatHex(randomValueHex.getBytes(StandardCharsets.UTF_8));
    }
}
