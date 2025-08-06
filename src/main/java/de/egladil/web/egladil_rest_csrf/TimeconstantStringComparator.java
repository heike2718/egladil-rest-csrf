package de.egladil.web.egladil_rest_csrf;

import java.security.MessageDigest;

/**
 * Wrapper for MessageDigests string comparison
 */
public class TimeconstantStringComparator {

    /**
     * Compares the strings. The calculation time depends only on the length of string1.
     *
     * @param string1 String or null
     * @param string2 String or null
     * @return boolean
     * @see @MessageDigest.isEqual()
     */
    public boolean isEqual(String string1, String string2) {

        if (string1 == null && string2 == null) {
            return true;
        }

        if (string1 == null || string2 == null) {
            return false;
        }

        return MessageDigest.isEqual(string1.getBytes(), string2.getBytes());
    }
}
