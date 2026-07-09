package com.promptshield.security.ratelimit;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InMemoryTokenBucketRateLimiterTest {

    @Test
    void allowsBurstThenRefillsGradually() {
        AtomicLong clock = new AtomicLong();
        InMemoryTokenBucketRateLimiter limiter = new InMemoryTokenBucketRateLimiter(
                new RateLimitPolicy(2, Duration.ofSeconds(1)), clock::get);

        assertTrue(limiter.tryAcquire("203.0.113.9").allowed());
        assertTrue(limiter.tryAcquire("203.0.113.9").allowed());

        RateLimitDecision rejected = limiter.tryAcquire("203.0.113.9");
        assertFalse(rejected.allowed());
        assertEquals(Duration.ofMillis(500), rejected.retryAfter());

        clock.addAndGet(Duration.ofMillis(500).toNanos());
        RateLimitDecision acceptedAfterRefill = limiter.tryAcquire("203.0.113.9");
        assertTrue(acceptedAfterRefill.allowed());
        assertEquals(0, acceptedAfterRefill.remainingTokens());
    }

    @Test
    void evictsIdleUntrustedClientKeys() {
        AtomicLong clock = new AtomicLong();
        InMemoryTokenBucketRateLimiter limiter = new InMemoryTokenBucketRateLimiter(
                new RateLimitPolicy(1, Duration.ofMinutes(1)), clock::get);
        limiter.tryAcquire("old-client");
        limiter.tryAcquire("active-client");

        clock.addAndGet(Duration.ofSeconds(10).toNanos());
        limiter.tryAcquire("active-client");

        assertEquals(1, limiter.evictIdleBuckets(Duration.ofSeconds(5)));
        assertEquals(1, limiter.bucketCount());
    }
}
