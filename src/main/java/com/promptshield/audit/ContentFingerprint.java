package com.promptshield.audit;

import java.nio.charset.StandardCharsets;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Cryptographic hashing helpers. Audit content correlation uses the keyed HMAC
 * method; the unkeyed SHA-256 helper is reserved for internal identifiers that
 * are never returned to clients.
 */
public final class ContentFingerprint {

    private ContentFingerprint() {
    }

    /**
     * Returns a lowercase hexadecimal SHA-256 fingerprint of the UTF-8 content.
     */
    public static String sha256(String content) {
        Objects.requireNonNull(content, "content must not be null");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException exception) {
            // SHA-256 is required by every Java implementation.
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    /** Returns a keyed HMAC-SHA-256 fingerprint as lowercase hexadecimal. */
    public static String hmacSha256(String content, byte[] key) {
        Objects.requireNonNull(content, "content must not be null");
        Objects.requireNonNull(key, "key must not be null");
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(content.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("HmacSHA256 is unavailable", exception);
        } catch (InvalidKeyException exception) {
            throw new IllegalArgumentException("invalid HMAC key", exception);
        }
    }
}
