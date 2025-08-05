package de.egladil.web.egladil_rest_csrf;

import java.security.MessageDigest;

/**
 * CsrfTokenValidator validates a signed csrf-token.
 */
public class CsrfTokenValidator {

    /**
     * Verifies the signature of the csrfToken.
     *
     * @param csrfToken
     * @param salt
     * @param validKey
     * @throws CsrfTokenValidationFailedException
     */
    public void verifyCsrfToken(String csrfToken, String salt, byte[] validKey) throws CsrfTokenValidationFailedException {

        if (csrfToken == null) {
            throw new CsrfTokenValidationFailedException("the csrfToken is null");
        }

        String[] parts = csrfToken.split("\\.");

        if (parts.length != 2) {
            throw new CsrfTokenValidationFailedException("the csrfToken does not have exactly two parts");
        }

        String hmacFromRequest = parts[0];
        String randomValueHex = parts[1];

        HmacGenerator hmacGenerator = new HmacGenerator();

        String messagePayload = hmacGenerator.getHmacMessagePayload(salt, randomValueHex);
        String expectedHmacHex = new HmacGenerator().generateHmac(messagePayload, HmacGenerator.HMAC_ALGORITHM, validKey);

        if (!MessageDigest.isEqual(expectedHmacHex.getBytes(), hmacFromRequest.getBytes())) {
            throw new CsrfTokenValidationFailedException("csrf-token signature verification failed");
        }
    }
}
