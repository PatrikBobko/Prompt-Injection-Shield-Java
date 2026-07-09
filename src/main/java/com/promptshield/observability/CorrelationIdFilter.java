package com.promptshield.observability;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Adds a safe correlation id to every response and makes it available to the
 * current request's log statements through SLF4J's MDC.
 *
 * <p>The filter is intentionally not annotated as a component. Register it in
 * application configuration once the log pattern and filter order are chosen.
 * This keeps the class reusable in applications with different tracing setups.</p>
 */
public final class CorrelationIdFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String correlationId = existingOrResolvedId(request);
        request.setAttribute(CorrelationId.REQUEST_ATTRIBUTE, correlationId);
        response.setHeader(CorrelationId.HEADER_NAME, correlationId);

        try (MDC.MDCCloseable ignored = MDC.putCloseable(CorrelationId.MDC_KEY, correlationId)) {
            filterChain.doFilter(request, response);
        }
    }

    @Override
    protected boolean shouldNotFilterAsyncDispatch() {
        // Re-establish the MDC on an async dispatch. The request attribute
        // keeps the same id rather than minting one for each dispatch.
        return false;
    }

    @Override
    protected boolean shouldNotFilterErrorDispatch() {
        // Error logs and error responses should remain correlated with the
        // request that caused them.
        return false;
    }

    private static String existingOrResolvedId(HttpServletRequest request) {
        Object existing = request.getAttribute(CorrelationId.REQUEST_ATTRIBUTE);
        if (existing instanceof String value && CorrelationId.isValid(value)) {
            return value;
        }
        return CorrelationId.resolve(request.getHeader(CorrelationId.HEADER_NAME));
    }
}
