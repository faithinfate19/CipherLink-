package com.cipherlink.cipherlink.service;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import org.springframework.stereotype.Service;

/** Generates opaque high-entropy API credentials and stores only their SHA-256 digest. */
@Service
public class AccessTokenService {
    private final SecureRandom random = new SecureRandom();
    public String generate() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    public String hash(String token) {
        validate(token);
        try { return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(token.getBytes(java.nio.charset.StandardCharsets.US_ASCII))); }
        catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
    public boolean matches(String token, String storedHash) {
        if (token == null || storedHash == null) return false;
        try {
            byte[] actual = Base64.getDecoder().decode(hash(token));
            byte[] expected = Base64.getDecoder().decode(storedHash);
            return MessageDigest.isEqual(actual, expected);
        } catch (IllegalArgumentException e) { return false; }
    }
    private static void validate(String token) {
        Objects.requireNonNull(token, "accessToken must not be null");
        try {
            byte[] raw = Base64.getUrlDecoder().decode(token);
            if (raw.length != 32 || token.length() != 43) throw new IllegalArgumentException("accessToken must be a 256-bit Base64URL token");
        } catch (IllegalArgumentException e) { throw new IllegalArgumentException("accessToken must be a 256-bit Base64URL token", e); }
    }
}
