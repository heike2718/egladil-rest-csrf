package de.egladil.web.egladil_rest_csrf;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class CsrfTokenValidatorTest {

    private final String salt = "idididsessionidididsessionidididsessionidsessionidsessionididids";
    private final CsrfTokenValidator csrfTokenValidator = new CsrfTokenValidator();

    @Test
    void should_verifyCsrfTokenThrowCsrfTokenValidationFailedException_when_onlyOnePart() {

        // Arragne
        final String csrfToken = "425369691";

        // Act
        CsrfTokenValidationFailedException exception = assertThrows(CsrfTokenValidationFailedException.class,
                () -> csrfTokenValidator.verifyCsrfToken(csrfToken, salt, new byte[64]));

        assertEquals("the csrfToken does not have exactly two parts", exception.getMessage());
    }

    @Test
    void should_verifyCsrfTokenThrowCsrfTokenValidationFailedException_when_threeParts() {

        // Arragne
        final String csrfToken = "425369691.21861217.5265182";

        // Act
        CsrfTokenValidationFailedException exception = assertThrows(CsrfTokenValidationFailedException.class,
                () -> csrfTokenValidator.verifyCsrfToken(csrfToken, salt, new byte[64]));

        assertEquals("the csrfToken does not have exactly two parts", exception.getMessage());
    }

    @Test
    void should_verifyCsrfTokenThrowCsrfTokenValidationFailedException_when_tokenIsNull() {

        // Arragne
        final String csrfToken = null;

        // Act
        CsrfTokenValidationFailedException exception = assertThrows(CsrfTokenValidationFailedException.class,
                () -> csrfTokenValidator.verifyCsrfToken(csrfToken, salt, new byte[64]));

        assertEquals("the csrfToken is null", exception.getMessage());
    }
}
