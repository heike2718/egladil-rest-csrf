# egladil-rest-csrf

This is a small library that supports csrf protection by implementing tools to generate and validate signed tokens as needed for the
the signed Double-Submit Cookie-Pattern recommended by OWASP: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#alternative-using-a-double-submit-cookie-pattern

## usage

### Generating secure random

Use

```
SecureRandomGenerator.generateSecureRandomHex(int numberOfByte)
```

in order to generate a hex encoded secure random.

For convenience, there is a method without parameter, that generates a 64-byte secure random.

### Generation of a signed stateless token

Use

```
new SignedTokenGenerator().genarateToken(String salt, byte[] signatureKey)
```

in order to generate a signed token. Hereby, salt shall be some value that is connected with the user, that is logged in, but not email or id in clear text. Recommendations: if you have a sessionId, this can be used as salt. If you don't have one, you can use

```
new HmacGenerator().generateHmac(String messagePayload, byte[] signatureKey);
```

in order to generate a secure hmac of a String derived from immutable attributes of the JWT as salt for the 
SignedTokenGenerator.

The generated token is stateless and does not need to be stored somewhere in the application or session. But:

**the salt is required for the token signature verification.** 

Thus, it must be some String that lives and is constant as long as a user session, either calculated from a JWT, for example, or a somewhere persisted sessionId.

### Verification of the signature

Use 

```
new SignedTokenValidator().verifyToken(String token, String salt, byte[] signatureKey)
```

in order to verify the tokens signature. Both salt and signatureKey must be the same as those used to generate the token.
