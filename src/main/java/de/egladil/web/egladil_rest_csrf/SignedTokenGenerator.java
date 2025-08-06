package de.egladil.web.egladil_rest_csrf;

/**
 * SignedTokenGenerator. Generates a signed token that is stateless itself.
 * <br>
 * <br>
 * This token can be used as stateless csrf-token in the double-submit-token-pattern for csrf protection.
 */
public class SignedTokenGenerator {

    /**
     * Generates a stateless token that consist of two parts seperated by a dot. The first part is an hmac, the second part a secure random.
     *
     * @param salt      String should be linked with a session like a sessionId or something that could be extracted from a JWT,
     *                  but not an email or ID of some user. Instead, use HmacGenerator first to generate a hmac of some attributes connected
     *                  with a stateless session in order to generate a stateless but reproducible salt value, as exactly the same salt is required for
     *                  the verification of the token signature.
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
