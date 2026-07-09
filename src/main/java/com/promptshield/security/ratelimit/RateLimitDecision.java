package com.promptshield.security.ratelimit;

import java.time.Duration;

/** The outcome of consuming one token from a requester's bucket. */
public record RateLimitDecision(boolean allowed, long remainingTokens, Duration retryAfter) {

    public RateLimitDecision {
        if (remainingTokens < 0) {
            throw new IllegalArgumentException("remainingTokens must not be negative");
        }
        if (retryAfter == null || retryAfter.isNegative()) {
            throw new IllegalArgumentException("retryAfter must not be negative");
        }
    }
}
