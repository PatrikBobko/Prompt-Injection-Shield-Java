package com.promptshield.audit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

/**
 * Produces keyed HMAC-SHA-256 fingerprints for audit correlation without
 * retaining submitted content or exposing an unkeyed dictionary oracle.
 */
@Component
public class ContentFingerprintService {

    private final byte[] key;

    public ContentFingerprintService(@Value("${app.audit.fingerprint-key}") String fingerprintKey) {
        if (fingerprintKey == null || fingerprintKey.length() < 16) {
            throw new IllegalArgumentException("app.audit.fingerprint-key must contain at least 16 characters");
        }
        this.key = fingerprintKey.getBytes(StandardCharsets.UTF_8);
    }

    public String fingerprint(String content) {
        return ContentFingerprint.hmacSha256(content, key);
    }
}
