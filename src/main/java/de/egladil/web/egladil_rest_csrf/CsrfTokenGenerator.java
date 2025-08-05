package de.egladil.web.egladil_rest_csrf;

/**
 * CsrfTokenGenerator. generates a signed csrf-token.
 */
public class CsrfTokenGenerator {

    /**
     * Generates a token that consist of two parts seperated by a dot. The first part is an hmac, the second part a secure random.
     *
     * @param salt     String should be linked with a session like a sessionId or something that could be extracted from a JWT, but not an email or ID of some user.
     * @param secretKey byte[] this is an application specific secret that will be used to sign the token. Minimum length is 64 byte.
     * @return String
     */
    public String generateToken(String salt, byte[] secretKey) {

        HmacGenerator hmacGenerator = new HmacGenerator();

        String randomValue = new SecureRandomGenerator().generateSecureRandomHex();
        String messagePayload = hmacGenerator.getHmacMessagePayload(salt, randomValue);
        String hmacHex = hmacGenerator.generateHmac(messagePayload, HmacGenerator.HMAC_ALGORITHM, secretKey);

        return hmacHex + "." + randomValue;
    }
}
