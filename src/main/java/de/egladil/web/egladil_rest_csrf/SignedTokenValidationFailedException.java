package de.egladil.web.egladil_rest_csrf;

/**
 * SignedTokenValidationFailedException.
 */
public class SignedTokenValidationFailedException extends RuntimeException {

    public SignedTokenValidationFailedException(String message) {
        super(message);
    }
}
