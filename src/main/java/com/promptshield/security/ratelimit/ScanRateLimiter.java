package com.promptshield.security.ratelimit;

/** A rate limiter that can be backed by local memory or a shared data store. */
public interface ScanRateLimiter {

    /** Attempts to consume one scan request for the supplied, non-blank client key. */
    RateLimitDecision tryAcquire(String key);

    /** Returns the active policy so HTTP responses can report the limit safely. */
    RateLimitPolicy policy();
}
