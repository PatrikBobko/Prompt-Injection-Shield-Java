package com.promptshield.config;

import com.promptshield.observability.CorrelationIdFilter;
import com.promptshield.observability.ScanMetrics;
import com.promptshield.observability.ScanMetricsMeterBinder;
import com.promptshield.security.RequestBodyLimitFilter;
import com.promptshield.security.ratelimit.ClientKeyResolver;
import com.promptshield.security.ratelimit.InMemoryTokenBucketRateLimiter;
import com.promptshield.security.ratelimit.RateLimitPolicy;
import com.promptshield.security.ratelimit.RedisFixedWindowRateLimiter;
import com.promptshield.security.ratelimit.ScanRateLimiter;
import io.micrometer.core.instrument.binder.MeterBinder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Duration;

/** Wires request correlation, privacy-safe metrics, and configurable abuse protection. */
@Configuration(proxyBeanMethods = false)
public class OperationalConfiguration {

    @Bean
    ScanMetrics scanMetrics() {
        return new ScanMetrics();
    }

    @Bean
    MeterBinder scanMetricsMeterBinder(ScanMetrics scanMetrics) {
        return new ScanMetricsMeterBinder(scanMetrics);
    }

    @Bean
    FilterRegistrationBean<CorrelationIdFilter> correlationIdFilterRegistration() {
        FilterRegistrationBean<CorrelationIdFilter> registration = new FilterRegistrationBean<>(new CorrelationIdFilter());
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }

    @Bean
    FilterRegistrationBean<RequestBodyLimitFilter> requestBodyLimitFilterRegistration(
            @Value("${app.request.max-body-bytes:8388608}") long maxBodyBytes) {
        FilterRegistrationBean<RequestBodyLimitFilter> registration = new FilterRegistrationBean<>(
                new RequestBodyLimitFilter(maxBodyBytes));
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 1);
        return registration;
    }

    @Bean
    RateLimitPolicy scanRateLimitPolicy(
            @Value("${app.rate-limit.capacity:60}") int capacity,
            @Value("${app.rate-limit.refill-period:1m}") Duration refillPeriod) {
        return new RateLimitPolicy(capacity, refillPeriod);
    }

    @Bean
    @ConditionalOnProperty(name = "app.rate-limit.backend", havingValue = "redis")
    ScanRateLimiter redisScanRateLimiter(StringRedisTemplate redisTemplate, RateLimitPolicy scanRateLimitPolicy) {
        return new RedisFixedWindowRateLimiter(redisTemplate, scanRateLimitPolicy);
    }

    @Bean
    @ConditionalOnProperty(name = "app.rate-limit.backend", havingValue = "memory", matchIfMissing = true)
    ScanRateLimiter inMemoryScanRateLimiter(RateLimitPolicy scanRateLimitPolicy) {
        return new InMemoryTokenBucketRateLimiter(scanRateLimitPolicy);
    }

    @Bean
    ClientKeyResolver scanClientKeyResolver() {
        ClientKeyResolver remoteAddress = ClientKeyResolver.remoteAddress();
        return request -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.isAuthenticated()
                    && !(authentication instanceof AnonymousAuthenticationToken)
                    && authentication.getName() != null && !authentication.getName().isBlank()) {
                return "subject:" + authentication.getName();
            }
            return remoteAddress.resolve(request);
        };
    }

}
