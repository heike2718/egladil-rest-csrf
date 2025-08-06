package de.egladil.web.egladil_secure_tokens;

/**
 * SignedTokenValidator verifies the signature of a signed token.
 */
public class SignedTokenValidator {

    /**
     * Verifies the signature of the token.
     *
     * @param token String. the token that signature has to be verified
     * @param salt String. the salt that was used for the generated token
     * @param validKey byte[]. the private key used to sign
     * @throws SignedTokenValidationFailedException when the verificytion fails
     */
    public void verifyToken(String token, String salt, byte[] validKey) throws SignedTokenValidationFailedException {

        if (token == null) {
            throw new SignedTokenValidationFailedException("the token is null");
        }

        String[] parts = token.split("\\.");

        if (parts.length != 2) {
            throw new SignedTokenValidationFailedException("the token does not have exactly two parts");
        }

        String hmacFromRequest = parts[0];
        String randomValueHex = parts[1];

        HmacGenerator hmacGenerator = new HmacGenerator();

        String messagePayload = hmacGenerator.getHmacMessagePayload(salt, randomValueHex);
        String expectedHmacHex = hmacGenerator.generateHmac(messagePayload, HmacGenerator.HMAC_ALGORITHM, validKey);

        if (!new TimeconstantStringComparator().isEqual(expectedHmacHex, hmacFromRequest)) {
            throw new SignedTokenValidationFailedException("token signature verification failed");
        }
    }
}
