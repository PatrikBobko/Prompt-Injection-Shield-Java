package com.promptshield.security.ratelimit;

import java.time.Duration;

/**
 * Token-bucket settings for one identity. A full bucket allows {@code capacity}
 * immediate requests, then gradually refills over {@code refillPeriod}.
 */
public record RateLimitPolicy(int capacity, Duration refillPeriod) {

    public RateLimitPolicy {
        if (capacity <= 0) {
            throw new IllegalArgumentException("capacity must be positive");
        }
        if (refillPeriod == null || refillPeriod.isZero() || refillPeriod.isNegative()) {
            throw new IllegalArgumentException("refillPeriod must be positive");
        }
        try {
            refillPeriod.toNanos();
        } catch (ArithmeticException ex) {
            throw new IllegalArgumentException("refillPeriod is too large", ex);
        }
    }

    long refillNanos() {
        return refillPeriod.toNanos();
    }
}
