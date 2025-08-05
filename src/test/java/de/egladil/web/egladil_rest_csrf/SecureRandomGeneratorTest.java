package de.egladil.web.egladil_rest_csrf;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.SecureRandom;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class SecureRandomGeneratorTest {

    private final SecureRandomGenerator secureRandomGenerator = new SecureRandomGenerator();

    static Stream<Arguments> provideInvalidKByteLenghts() {
        return Stream.of(
                Arguments.of(0),
                Arguments.of(1), // too short
                Arguments.of( 31) // minimum boundary
        );
    }

    @ParameterizedTest
    @MethodSource("provideInvalidKByteLenghts")
    void generateHmac_generateSecureRandomHexRejectInvalidByteLength(Integer invalidByteLength) {
        assertThrows(IllegalArgumentException.class,
                () -> secureRandomGenerator.generateSecureRandomHex(invalidByteLength));
    }

    @Test
    void should_generateSecureRandomHex_generateASecureRandomHexStringOfLength128() {
        // Act
        String generatedToken = secureRandomGenerator.generateSecureRandomHex();

        // Assert
        assertNotNull(generatedToken);
        assertEquals(128, generatedToken.length()); // 64 bytes → 128 hex chars

        // Verify it's proper hex
        assertTrue(generatedToken.matches("[0-9a-f]{128}"));

    }

    @Test
    void should_generateSecureRandomHex_useSecureRandom() {
        // Verify SecureRandom was called (using Mockito)
        SecureRandom mockRandom = mock(SecureRandom.class);
        SecureRandomGenerator generator = new SecureRandomGenerator(mockRandom);

        generator.generateSecureRandomHex(64);
        verify(mockRandom).nextBytes(any());
    }

    @Test
    void should_generateSecureRandomHex_generateASecureRandomHexStringOfGivenLength() {

        // Arrange
        int numberOfBytes = 32;

        // Act
        String generatedToken = secureRandomGenerator.generateSecureRandomHex(numberOfBytes);

        // Assert
        assertNotNull(generatedToken);
        assertEquals(64, generatedToken.length()); // 32 bytes → 64 hex chars

        // Verify it's proper hex
        assertTrue(generatedToken.matches("[0-9a-f]{64}"));

    }


}
