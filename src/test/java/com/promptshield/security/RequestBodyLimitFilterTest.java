package com.promptshield.security;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

class RequestBodyLimitFilterTest {

    private final RequestBodyLimitFilter filter = new RequestBodyLimitFilter(4);

    @Test
    void rejectsKnownOversizedScanWithoutCallingTheChain() throws Exception {
        MockHttpServletRequest request = requestWithContent("12345");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean called = new AtomicBoolean();

        filter.doFilter(request, response, (ignoredRequest, ignoredResponse) -> called.set(true));

        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(response.getContentAsString()).contains("configured limit");
        assertThat(called).isFalse();
    }

    @Test
    void rejectsChunkedLikePayloadWhenTheChainReadsPastTheLimit() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/scan") {
            @Override
            public long getContentLengthLong() {
                return -1;
            }
        };
        request.setContent("12345".getBytes(StandardCharsets.UTF_8));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, readEntireBody());

        assertThat(response.getStatus()).isEqualTo(413);
    }

    @Test
    void doesNotLimitOtherEndpoints() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/other");
        request.setContent("12345".getBytes(StandardCharsets.UTF_8));
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicBoolean called = new AtomicBoolean();

        filter.doFilter(request, response, (ignoredRequest, ignoredResponse) -> called.set(true));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(called).isTrue();
    }

    private static MockHttpServletRequest requestWithContent(String content) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/scan");
        request.setContent(content.getBytes(StandardCharsets.UTF_8));
        return request;
    }

    private static FilterChain readEntireBody() {
        return (request, response) -> {
            byte[] buffer = new byte[16];
            while (request.getInputStream().read(buffer) != -1) {
                // Consume the body exactly as a message converter would.
            }
        };
    }
}
