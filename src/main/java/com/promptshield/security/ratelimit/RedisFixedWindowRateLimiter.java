package com.promptshield.security.ratelimit;

import com.promptshield.audit.ContentFingerprint;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * Atomic Redis-backed fixed-window limiter for horizontally scaled deployments.
 * Client identities are SHA-256 hashed before becoming Redis keys.
 */
public final class RedisFixedWindowRateLimiter implements ScanRateLimiter {

    private static final DefaultRedisScript<List> ACQUIRE_SCRIPT = new DefaultRedisScript<>("""
            local count = redis.call('INCR', KEYS[1])
            if count == 1 then
              redis.call('PEXPIRE', KEYS[1], ARGV[1])
            end
            local ttl = redis.call('PTTL', KEYS[1])
            local capacity = tonumber(ARGV[2])
            local allowed = 0
            if count <= capacity then
              allowed = 1
            end
            local remaining = capacity - count
            if remaining < 0 then
              remaining = 0
            end
            return {allowed, remaining, ttl}
            """, List.class);

    private final StringRedisTemplate redisTemplate;
    private final RateLimitPolicy policy;

    public RedisFixedWindowRateLimiter(StringRedisTemplate redisTemplate, RateLimitPolicy policy) {
        this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate must not be null");
        this.policy = Objects.requireNonNull(policy, "policy must not be null");
    }

    @Override
    public RateLimitDecision tryAcquire(String key) {
        if (key == null || key.isBlank()) {
            throw new IllegalArgumentException("key must not be blank");
        }
        long windowMillis = Math.max(1L, policy.refillPeriod().toMillis());
        List<?> outcome = redisTemplate.execute(
                ACQUIRE_SCRIPT,
                List.of(redisKey(key)),
                Long.toString(windowMillis),
                Integer.toString(policy.capacity()));
        if (outcome == null || outcome.size() != 3) {
            throw new IllegalStateException("Redis rate-limit script returned an invalid result");
        }

        boolean allowed = number(outcome.get(0)) == 1L;
        long remaining = Math.max(0L, number(outcome.get(1)));
        long retryMillis = Math.max(1L, number(outcome.get(2)));
        return new RateLimitDecision(allowed, remaining, allowed ? Duration.ZERO : Duration.ofMillis(retryMillis));
    }

    @Override
    public RateLimitPolicy policy() {
        return policy;
    }

    private static String redisKey(String clientKey) {
        return "promptshield:rate-limit:" + ContentFingerprint.sha256(clientKey);
    }

    private static long number(Object value) {
        if (value instanceof Number number) {
            return number.longValue();
        }
        try {
            return Long.parseLong(String.valueOf(value));
        } catch (NumberFormatException exception) {
            throw new IllegalStateException("Redis rate-limit script returned a non-numeric value", exception);
        }
    }
}
