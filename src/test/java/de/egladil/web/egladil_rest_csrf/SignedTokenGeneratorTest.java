package de.egladil.web.egladil_rest_csrf;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class SignedTokenGeneratorTest {

    private byte[] validKey;

    private final SignedTokenGenerator tokenGenerator = new SignedTokenGenerator();

    @BeforeEach
    void setUp() {
        String text = "secret-for-test-purpose";
        byte[] key = (text.repeat(3)).getBytes(StandardCharsets.UTF_8);
        validKey = Arrays.copyOf(key, 64); // Ensure exactly 64 bytes
    }

    @Test
    void should_generateAToken() {

        // Arrange
        String salt = "this-could-be-a-session-id";

        // Act
        String token = tokenGenerator.generateToken(salt, validKey);

        // Assert
        assertNotNull(token);
        String[] parts = token.split("\\.");

        assertEquals(2, parts.length);
    }
}
