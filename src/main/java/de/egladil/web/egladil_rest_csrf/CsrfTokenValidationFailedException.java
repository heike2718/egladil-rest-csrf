package de.egladil.web.egladil_rest_csrf;

/**
 * CsrfTokenValidationFailedException.
 */
public class CsrfTokenValidationFailedException extends RuntimeException {

    public CsrfTokenValidationFailedException(String message) {
        super(message);
    }
}
