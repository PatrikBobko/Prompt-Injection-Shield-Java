package com.promptshield.security.ratelimit;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Objects;

/**
 * Servlet filter that protects only {@code POST /api/v1/scan} with a supplied
 * limiter. Register it explicitly so production can choose a policy, a key
 * strategy and an order relative to authentication.
 */
public final class ScanRateLimitFilter extends OncePerRequestFilter {

    private static final String SCAN_PATH = "/api/v1/scan";

    private final ScanRateLimiter limiter;
    private final ClientKeyResolver clientKeyResolver;

    public ScanRateLimitFilter(ScanRateLimiter limiter, ClientKeyResolver clientKeyResolver) {
        this.limiter = Objects.requireNonNull(limiter, "limiter must not be null");
        this.clientKeyResolver = Objects.requireNonNull(clientKeyResolver, "clientKeyResolver must not be null");
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !"POST".equalsIgnoreCase(request.getMethod()) || !SCAN_PATH.equals(pathWithinApplication(request));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        RateLimitDecision decision = limiter.tryAcquire(clientKeyResolver.resolve(request));
        response.setHeader("X-RateLimit-Limit", String.valueOf(limiter.policy().capacity()));
        response.setHeader("X-RateLimit-Remaining", String.valueOf(decision.remainingTokens()));

        if (decision.allowed()) {
            filterChain.doFilter(request, response);
            return;
        }

        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setHeader("Retry-After", String.valueOf(retryAfterSeconds(decision.retryAfter())));
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"rate limit exceeded\"}");
    }

    private static String pathWithinApplication(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        String requestUri = request.getRequestURI();
        return requestUri.startsWith(contextPath) ? requestUri.substring(contextPath.length()) : requestUri;
    }

    private static long retryAfterSeconds(Duration retryAfter) {
        long nanos = retryAfter.toNanos();
        long seconds = (nanos + 999_999_999L) / 1_000_000_000L;
        return Math.max(1L, seconds);
    }
}
