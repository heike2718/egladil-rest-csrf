package de.egladil.web.egladil_secure_tokens;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TimeconstantStringComparatorTest {

    private final TimeconstantStringComparator stringComparator = new TimeconstantStringComparator();

    @Test
    void should_isEqual_returnTrue_when_stringsAreEqual() {

        // Arrange
        String string = "idididsessionidididsessionidididsessionidsessionidsessionididids";

        // Act + Assert
        assertTrue(stringComparator.isEqual(string, string));

    }

    @Test
    void should_isEqual_returnTrue_when_stringsAreNull() {

        // Act + Assert
        assertTrue(stringComparator.isEqual(null, null));

    }

    @Test
    void should_isEqual_returnFalse_when_stringsAreNotEqual() {

        // Arrange
        String string = "idididsessionidididsessionidididsessionidsessionidsessionididids";

        // Act + Assert
        assertFalse(stringComparator.isEqual(string, string + "s"));

    }

    @Test
    void should_isEqual_returnFalse_when_firstIsNull() {

        // Arrange
        String string = "idididsessionidididsessionidididsessionidsessionidsessionididids";

        // Act + Assert
        assertFalse(stringComparator.isEqual(null, string));

    }

    @Test
    void should_isEqual_returnFalse_when_secondIsNull() {

        // Arrange
        String string = "idididsessionidididsessionidididsessionidsessionidsessionididids";

        // Act + Assert
        assertFalse(stringComparator.isEqual(string, null));

    }
}
