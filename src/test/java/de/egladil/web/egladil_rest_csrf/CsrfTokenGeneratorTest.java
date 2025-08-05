package de.egladil.web.egladil_rest_csrf;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class CsrfTokenGeneratorTest {

    private byte[] validKey;

    private final CsrfTokenGenerator csrfTokenGenerator = new CsrfTokenGenerator();

    @BeforeEach
    void setUp() {
        String text = "secret-for-test-purpose";
        byte[] key = (text.repeat(3)).getBytes(StandardCharsets.UTF_8);
        validKey = Arrays.copyOf(key, 64); // Ensure exactly 64 bytes
    }

    @Test
    void should_generateACsrfToken() {

        // Arrange
        String salt = "this-could-be-a-session-id";

        // Act
        String csrfToken = csrfTokenGenerator.generateToken(salt, validKey);

        // Assert
        assertNotNull(csrfToken);
        String[] parts = csrfToken.split("\\.");

        assertEquals(2, parts.length);
    }
}
