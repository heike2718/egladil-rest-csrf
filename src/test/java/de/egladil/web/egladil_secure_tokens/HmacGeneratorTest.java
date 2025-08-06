package de.egladil.web.egladil_secure_tokens;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

public class HmacGeneratorTest {

    private final HmacGenerator hmacGenerator = new HmacGenerator();
    private byte[] validKey;
    private final String validAlgorithm = "HmacSHA256";
    private final String testMessage = "test message";

    static Stream<Arguments> provideInvalidKeys() {
        return Stream.of(
                Arguments.of(new byte[0]),                 // empty key
                Arguments.of(new byte[1]),                 // too short
                Arguments.of(new byte[63]),                // boundary case
                Arguments.of(new byte[65])               // boundary case
        );
    }

    @BeforeEach
    void setUp() {
        String text = "secret-for-test-purpose";
        byte[] key = (text.repeat(3)).getBytes(StandardCharsets.UTF_8);
        validKey = Arrays.copyOf(key, 64); // Ensure exactly 64 bytes
    }

    @ParameterizedTest
    @MethodSource("provideInvalidKeys")
    void generateHmac_shouldRejectInvalidKeys(byte[] invalidKey) {
        assertThrows(IllegalArgumentException.class,
                () -> hmacGenerator.generateHmac(testMessage, validAlgorithm, invalidKey));
    }


    @Test
    void generateHmac_shouldReturnValidHexStringWithValidInput() {
        // Arrange
        // validKey initialized with zeros for testing (in real usage use proper random key)

        // Act
        String result = hmacGenerator.generateHmac(testMessage, validAlgorithm, validKey);

        // Assert
        // @formatter:off
        assertAll(() -> assertNotNull(result),
                () -> assertFalse(result.isEmpty()),
                () -> assertEquals(64, result.length()),
                () -> assertDoesNotThrow(() -> HexFormat.of().parseHex(result)));
        // @formatter:on
    }

    @Test
    void generateHmac_shouldThrowSecurityExceptionOnNoSuchAlgorithmException() {
        // Arrange
        String invalidAlgorithm = "HmacNonExistentAlgorithm";

        // Act & Assert
        Exception exception = assertThrows(SecurityException.class,
                () -> hmacGenerator.generateHmac(testMessage, invalidAlgorithm, validKey));

        assertInstanceOf(NoSuchAlgorithmException.class, exception.getCause());
        assertEquals("Failed to generate hmac", exception.getMessage());
    }

    @Test
    void generateHmac_willNotThrowSecurityExceptionForWeekKeys() {
        // Arrange
        byte[] weakKey = new byte[64];

        // Act & Assert
        assertDoesNotThrow(
                () -> hmacGenerator.generateHmac(testMessage, validAlgorithm, weakKey),
                "JCA should accept weak keys for HMAC - if this fails, Java's security " +
                        "policy may have changed to reject weak keys");
    }

    @Test
    void generateHmac_shouldThrowIllegalArgumentExceptionOnNullMessage() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class,
                () -> hmacGenerator.generateHmac(null, validAlgorithm, validKey));
    }

    @Test
    void generateHmac_shouldThrowIllegalArgumentExceptionOnNullAlgorithm() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class,
                () -> hmacGenerator.generateHmac(testMessage, null, validKey));
    }

    @Test
    void generateHmac_shouldThrowIllegalArgumentExceptionOnNullKey() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class,
                () -> hmacGenerator.generateHmac(testMessage, validAlgorithm, null));
    }

    @Test
    void generateHmac_shouldProduceDifferentOutputForDifferentMessages() {
        // Arrange
        String message1 = "message1";
        String message2 = "message2";

        // Act
        String hmac1 = hmacGenerator.generateHmac(message1, validAlgorithm, validKey);
        String hmac2 = hmacGenerator.generateHmac(message2, validAlgorithm, validKey);

        // Assert
        assertNotEquals(hmac1, hmac2);
    }

    @Test
    void generateHmac_shouldProduceDifferentOutputForDifferentKeys() {
        // Arrange
        String text = "test-secret-key";
        byte[] key = (text.repeat(20)).getBytes(StandardCharsets.UTF_8);
        key = Arrays.copyOf(key, 64); // Ensure exactly 64 bytes

        assertEquals(64, key.length);

        // Act
        String hmac1 = hmacGenerator.generateHmac(testMessage, validAlgorithm, validKey);
        String hmac2 = hmacGenerator.generateHmac(testMessage, validAlgorithm, key);

        // Assert
        assertNotEquals(hmac1, hmac2);
    }

    @Test
    void generateHmac_shouldBeDeterministicWithSameInput() {
        // Act
        String hmac1 = hmacGenerator.generateHmac(testMessage, validKey);
        String hmac2 = hmacGenerator.generateHmac(testMessage, validKey);

        // Assert
        assertEquals(hmac1, hmac2);
    }

    @Test
    void should_getHmacMessagePayload_work() {

        // Arrange
        String salt = "salt";
        String randomHex = "4175417";

        String expected = "4!salt!7!34313735343137";

        // Act
        String actual = hmacGenerator.getHmacMessagePayload(salt, randomHex);

        // Assert
        assertEquals(expected, actual);

    }

    @Test
    void should_public_generateHmac_work() {

       // Act
        String actual = hmacGenerator.generateHmac(testMessage, validKey);

        // Assert
        assertEquals("1ef70f5078975bb00ad4e7809510afa81412defdfdcc58c329d6ce5502e70a7d", actual);

    }
}
