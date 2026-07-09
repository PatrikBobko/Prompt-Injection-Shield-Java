package com.promptshield.observability;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class CorrelationIdFilterTest {

    private final CorrelationIdFilter filter = new CorrelationIdFilter();

    @AfterEach
    void clearMdc() {
        MDC.clear();
    }

    @Test
    void returnsAndLogsTheSafeCallerSuppliedId() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/health");
        request.addHeader(CorrelationId.HEADER_NAME, "client-request-42");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<String> idSeenInsideChain = new AtomicReference<>();

        filter.doFilter(request, response,
                (ignoredRequest, ignoredResponse) -> idSeenInsideChain.set(MDC.get(CorrelationId.MDC_KEY)));

        assertEquals("client-request-42", response.getHeader(CorrelationId.HEADER_NAME));
        assertEquals("client-request-42", idSeenInsideChain.get());
        assertNull(MDC.get(CorrelationId.MDC_KEY));
    }

    @Test
    void reusesTheRequestIdOnRedispatch() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/health");
        request.setAttribute(CorrelationId.REQUEST_ATTRIBUTE, "original-request-9");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, (ignoredRequest, ignoredResponse) -> { });

        assertEquals("original-request-9", response.getHeader(CorrelationId.HEADER_NAME));
    }
}
