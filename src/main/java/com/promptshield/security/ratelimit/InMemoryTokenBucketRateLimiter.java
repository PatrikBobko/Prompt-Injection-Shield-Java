package com.promptshield.security.ratelimit;

import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Thread-safe token-bucket limiter suitable for one application instance.
 *
 * <p>For a horizontally scaled deployment, replace this implementation with a
 * shared Redis/Bucket4j strategy. A small eviction API is provided so callers
 * can remove identities that have been idle for a chosen period.</p>
 */
public final class InMemoryTokenBucketRateLimiter implements ScanRateLimiter {

    private final RateLimitPolicy policy;
    private final LongSupplier nanoClock;
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    public InMemoryTokenBucketRateLimiter(RateLimitPolicy policy) {
        this(policy, System::nanoTime);
    }

    InMemoryTokenBucketRateLimiter(RateLimitPolicy policy, LongSupplier nanoClock) {
        this.policy = Objects.requireNonNull(policy, "policy must not be null");
        this.nanoClock = Objects.requireNonNull(nanoClock, "nanoClock must not be null");
    }

    /** Attempts to consume one token for {@code key}. */
    public RateLimitDecision tryAcquire(String key) {
        if (key == null || key.isBlank()) {
            throw new IllegalArgumentException("key must not be blank");
        }
        long now = nanoClock.getAsLong();
        Bucket bucket = buckets.computeIfAbsent(key, ignored -> new Bucket(policy.capacity(), now));
        return bucket.tryAcquire(policy, now);
    }

    /** The immutable policy used by this limiter. */
    public RateLimitPolicy policy() {
        return policy;
    }

    /** Number of tracked identities. Useful for capacity monitoring. */
    public int bucketCount() {
        return buckets.size();
    }

    /**
     * Removes identities unused for at least {@code maxIdle}. Invoke on a
     * scheduled maintenance task when keys originate from untrusted clients.
     *
     * @return number of removed buckets
     */
    public int evictIdleBuckets(Duration maxIdle) {
        if (maxIdle == null || maxIdle.isNegative() || maxIdle.isZero()) {
            throw new IllegalArgumentException("maxIdle must be positive");
        }
        final long maxIdleNanos;
        try {
            maxIdleNanos = maxIdle.toNanos();
        } catch (ArithmeticException ex) {
            throw new IllegalArgumentException("maxIdle is too large", ex);
        }

        long now = nanoClock.getAsLong();
        int removed = 0;
        for (Map.Entry<String, Bucket> entry : buckets.entrySet()) {
            Bucket bucket = entry.getValue();
            if (bucket.isIdleAtLeast(now, maxIdleNanos) && buckets.remove(entry.getKey(), bucket)) {
                removed++;
            }
        }
        return removed;
    }

    private static final class Bucket {

        private double tokens;
        private long lastRefillNanos;
        private long lastAccessNanos;

        private Bucket(int capacity, long now) {
            this.tokens = capacity;
            this.lastRefillNanos = now;
            this.lastAccessNanos = now;
        }

        private synchronized RateLimitDecision tryAcquire(RateLimitPolicy policy, long now) {
            refill(policy, now);
            lastAccessNanos = now;
            if (tokens >= 1.0d) {
                tokens -= 1.0d;
                return new RateLimitDecision(true, (long) Math.floor(tokens), Duration.ZERO);
            }

            double missingTokenFraction = 1.0d - tokens;
            long retryNanos = nanosUntilOneToken(missingTokenFraction, policy);
            return new RateLimitDecision(false, 0L, Duration.ofNanos(retryNanos));
        }

        private synchronized boolean isIdleAtLeast(long now, long idleNanos) {
            long elapsed = now - lastAccessNanos;
            return elapsed >= idleNanos && elapsed >= 0L;
        }

        private void refill(RateLimitPolicy policy, long now) {
            long elapsed = now - lastRefillNanos;
            if (elapsed <= 0L) {
                return;
            }
            double replenished = (double) elapsed * policy.capacity() / policy.refillNanos();
            tokens = Math.min(policy.capacity(), tokens + replenished);
            lastRefillNanos = now;
        }

        private static long nanosUntilOneToken(double missingTokenFraction, RateLimitPolicy policy) {
            double nanos = missingTokenFraction * policy.refillNanos() / policy.capacity();
            if (nanos >= Long.MAX_VALUE) {
                return Long.MAX_VALUE;
            }
            return Math.max(1L, (long) Math.ceil(nanos));
        }
    }
}
