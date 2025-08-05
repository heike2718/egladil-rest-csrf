package de.egladil.web.egladil_rest_csrf;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class CombinedGeneratorAndValidatorTest {

    private final String salt = "idididsessionidididsessionidididsessionidsessionidsessionididids";

    private byte[] validKey;

    private final CsrfTokenGenerator csrfTokenGenerator = new CsrfTokenGenerator();

    private final CsrfTokenValidator csrfTokenValidator = new CsrfTokenValidator();

    @BeforeEach
    void setUp() {
        String text = "secret-for-test-purpose";
        byte[] key = (text.repeat(3)).getBytes(StandardCharsets.UTF_8);
        validKey = Arrays.copyOf(key, 64); // Ensure exactly 64 bytes
    }

    @Test
    void should_theGeneratedTokenBeValid() {

        String csrfToken = csrfTokenGenerator.generateToken(salt, validKey);

        assertDoesNotThrow(() ->
                csrfTokenValidator.verifyCsrfToken(csrfToken, salt, validKey));
    }

    @Test
    void should_validationFail_when_tokenChanged() {

        String csrfToken = "2418649169.78305717501730";

        CsrfTokenValidationFailedException exception = assertThrows(CsrfTokenValidationFailedException.class,
                () -> csrfTokenValidator.verifyCsrfToken(csrfToken, salt, validKey));

        assertEquals("csrf-token signature verification failed", exception.getMessage());
    }
}
