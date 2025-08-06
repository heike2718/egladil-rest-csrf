package de.egladil.web.egladil_secure_tokens;

/**
 * SignedTokenValidationFailedException.
 */
public class SignedTokenValidationFailedException extends RuntimeException {

    public SignedTokenValidationFailedException(String message) {
        super(message);
    }
}
