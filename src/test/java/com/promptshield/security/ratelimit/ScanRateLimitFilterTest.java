package com.promptshield.security.ratelimit;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanRateLimitFilterTest {

    @Test
    void rejectsASecondScanFromTheSameClientWithUsefulHeaders() throws Exception {
        InMemoryTokenBucketRateLimiter limiter = new InMemoryTokenBucketRateLimiter(
                new RateLimitPolicy(1, Duration.ofMinutes(1)));
        ScanRateLimitFilter filter = new ScanRateLimitFilter(limiter, ClientKeyResolver.remoteAddress());

        MockHttpServletRequest firstRequest = scanRequest();
        MockHttpServletResponse firstResponse = new MockHttpServletResponse();
        AtomicBoolean chainCalled = new AtomicBoolean();
        filter.doFilter(firstRequest, firstResponse,
                (ignoredRequest, ignoredResponse) -> chainCalled.set(true));

        MockHttpServletResponse rejectedResponse = new MockHttpServletResponse();
        filter.doFilter(scanRequest(), rejectedResponse, (ignoredRequest, ignoredResponse) -> { });

        assertTrue(chainCalled.get());
        assertEquals("1", firstResponse.getHeader("X-RateLimit-Limit"));
        assertEquals(429, rejectedResponse.getStatus());
        assertEquals("0", rejectedResponse.getHeader("X-RateLimit-Remaining"));
        assertEquals("60", rejectedResponse.getHeader("Retry-After"));
        assertEquals("{\"error\":\"rate limit exceeded\"}", rejectedResponse.getContentAsString());
    }

    @Test
    void bypassesNonScanEndpoints() throws Exception {
        InMemoryTokenBucketRateLimiter limiter = new InMemoryTokenBucketRateLimiter(
                new RateLimitPolicy(1, Duration.ofMinutes(1)));
        ScanRateLimitFilter filter = new ScanRateLimitFilter(limiter, ClientKeyResolver.remoteAddress());
        MockHttpServletRequest healthRequest = new MockHttpServletRequest("GET", "/api/v1/health");
        AtomicBoolean chainCalled = new AtomicBoolean();

        filter.doFilter(healthRequest, new MockHttpServletResponse(),
                (ignoredRequest, ignoredResponse) -> chainCalled.set(true));

        assertTrue(chainCalled.get());
        assertEquals(0, limiter.bucketCount());
    }

    private static MockHttpServletRequest scanRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/scan");
        request.setRemoteAddr("203.0.113.9");
        return request;
    }
}
