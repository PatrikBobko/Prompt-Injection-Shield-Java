package com.promptshield.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Enforces a streaming byte limit for scan requests, including chunked requests
 * that omit {@code Content-Length}. This complements the character-level Bean
 * Validation limit on {@code ScanRequest.content}.
 */
public final class RequestBodyLimitFilter extends OncePerRequestFilter {

    private static final String SCAN_PATH = "/api/v1/scan";

    private final long maxBytes;

    public RequestBodyLimitFilter(long maxBytes) {
        if (maxBytes <= 0) {
            throw new IllegalArgumentException("maxBytes must be positive");
        }
        this.maxBytes = maxBytes;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !"POST".equalsIgnoreCase(request.getMethod()) || !SCAN_PATH.equals(pathWithinApplication(request));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (request.getContentLengthLong() > maxBytes) {
            reject(response);
            return;
        }
        try {
            filterChain.doFilter(new LimitedRequest(request, maxBytes), response);
        } catch (RequestBodyTooLargeException exception) {
            if (!response.isCommitted()) {
                reject(response);
            }
        }
    }

    private static void reject(HttpServletResponse response) throws IOException {
        response.setStatus(HttpStatus.PAYLOAD_TOO_LARGE.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"status\":413,\"error\":\"request body exceeds the configured limit\"}");
    }

    private static String pathWithinApplication(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        String requestUri = request.getRequestURI();
        return requestUri.startsWith(contextPath) ? requestUri.substring(contextPath.length()) : requestUri;
    }

    private static final class LimitedRequest extends HttpServletRequestWrapper {

        private final ServletInputStream inputStream;
        private final Charset charset;

        private LimitedRequest(HttpServletRequest request, long maxBytes) {
            super(request);
            this.inputStream = new LimitedServletInputStream(request, maxBytes);
            String encoding = request.getCharacterEncoding();
            this.charset = encoding == null ? StandardCharsets.UTF_8 : Charset.forName(encoding);
        }

        @Override
        public ServletInputStream getInputStream() {
            return inputStream;
        }

        @Override
        public BufferedReader getReader() {
            return new BufferedReader(new InputStreamReader(inputStream, charset));
        }
    }

    private static final class LimitedServletInputStream extends ServletInputStream {

        private final ServletInputStream delegate;
        private long remaining;

        private LimitedServletInputStream(HttpServletRequest request, long maxBytes) {
            try {
                this.delegate = request.getInputStream();
            } catch (IOException exception) {
                throw new IllegalStateException("unable to read request input stream", exception);
            }
            this.remaining = maxBytes;
        }

        @Override
        public int read() throws IOException {
            ensureCapacity();
            int value = delegate.read();
            if (value != -1) {
                remaining--;
            }
            return value;
        }

        @Override
        public int read(byte[] bytes, int offset, int length) throws IOException {
            if (length == 0) {
                return 0;
            }
            ensureCapacity();
            int boundedLength = (int) Math.min(length, remaining);
            int read = delegate.read(bytes, offset, boundedLength);
            if (read != -1) {
                remaining -= read;
            }
            return read;
        }

        @Override
        public boolean isFinished() {
            return delegate.isFinished();
        }

        @Override
        public boolean isReady() {
            return delegate.isReady();
        }

        @Override
        public void setReadListener(ReadListener readListener) {
            delegate.setReadListener(readListener);
        }

        private void ensureCapacity() throws IOException {
            if (remaining > 0) {
                return;
            }
            if (delegate.read() != -1) {
                throw new RequestBodyTooLargeException();
            }
        }
    }

    private static final class RequestBodyTooLargeException extends IOException {
    }
}
