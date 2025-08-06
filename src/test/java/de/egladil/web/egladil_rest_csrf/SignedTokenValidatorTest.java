package de.egladil.web.egladil_rest_csrf;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class SignedTokenValidatorTest {

    private final String salt = "idididsessionidididsessionidididsessionidsessionidsessionididids";
    private final SignedTokenValidator signedTokenValidator = new SignedTokenValidator();

    @Test
    void should_verifyTokenThrowSignedTokenValidationFailedException_when_onlyOnePart() {

        // Arragne
        final String token = "425369691";

        // Act
        SignedTokenValidationFailedException exception = assertThrows(SignedTokenValidationFailedException.class,
                () -> signedTokenValidator.verifyToken(token, salt, new byte[64]));

        assertEquals("the token does not have exactly two parts", exception.getMessage());
    }

    @Test
    void should_verifyTokenThrowSignedTokenValidationFailedException_when_threeParts() {

        // Arragne
        final String token = "425369691.21861217.5265182";

        // Act
        SignedTokenValidationFailedException exception = assertThrows(SignedTokenValidationFailedException.class,
                () -> signedTokenValidator.verifyToken(token, salt, new byte[64]));

        assertEquals("the token does not have exactly two parts", exception.getMessage());
    }

    @Test
    void should_verifyTokenThrowSignedTokenValidationFailedException_when_tokenIsNull() {

        // Arragne
        final String token = null;

        // Act
        SignedTokenValidationFailedException exception = assertThrows(SignedTokenValidationFailedException.class,
                () -> signedTokenValidator.verifyToken(token, salt, new byte[64]));

        assertEquals("the token is null", exception.getMessage());
    }
}
