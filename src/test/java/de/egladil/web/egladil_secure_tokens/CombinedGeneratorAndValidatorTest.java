package de.egladil.web.egladil_secure_tokens;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class CombinedGeneratorAndValidatorTest {

    private final String salt = "idididsessionidididsessionidididsessionidsessionidsessionididids";

    private byte[] validKey;

    private final SignedTokenGenerator tokenGenerator = new SignedTokenGenerator();

    private final SignedTokenValidator tokenValidator = new SignedTokenValidator();

    @BeforeEach
    void setUp() {
        String text = "secret-for-test-purpose";
        byte[] key = (text.repeat(3)).getBytes(StandardCharsets.UTF_8);
        validKey = Arrays.copyOf(key, 64); // Ensure exactly 64 bytes
    }

    @Test
    void should_theGeneratedTokenBeValid() {

        String token = tokenGenerator.generateToken(salt, validKey);

        assertDoesNotThrow(() ->
                tokenValidator.verifyToken(token, salt, validKey));
    }

    @Test
    void should_validationFail_when_tokenChanged() {

        String token = "2418649169.78305717501730";

        SignedTokenValidationFailedException exception = assertThrows(SignedTokenValidationFailedException.class,
                () -> tokenValidator.verifyToken(token, salt, validKey));

        assertEquals("token signature verification failed", exception.getMessage());
    }
}
