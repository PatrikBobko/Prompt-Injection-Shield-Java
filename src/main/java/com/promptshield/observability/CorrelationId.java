package com.promptshield.observability;

import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Normalises the request identifier used to correlate logs, API responses and
 * downstream calls. Values supplied by clients are deliberately constrained
 * before they reach logs to prevent log-forging through control characters.
 */
public final class CorrelationId {

    /** HTTP header exposed to API clients and propagated to downstream services. */
    public static final String HEADER_NAME = "X-Correlation-Id";

    /** MDC key used by the logging pattern. */
    public static final String MDC_KEY = "correlationId";

    /** Request attribute used to retain the id across servlet redispatches. */
    public static final String REQUEST_ATTRIBUTE = CorrelationId.class.getName() + ".value";

    private static final int MAX_LENGTH = 128;
    private static final Pattern SAFE_VALUE = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,127}");

    private CorrelationId() {
    }

    /**
     * Returns a safe caller-supplied value, or a new UUID when the supplied
     * value is absent or unsuitable for logs and HTTP headers.
     */
    public static String resolve(String candidate) {
        return isValid(candidate) ? candidate : UUID.randomUUID().toString();
    }

    /** Returns whether a value can safely be reused as a correlation id. */
    public static boolean isValid(String value) {
        return value != null && value.length() <= MAX_LENGTH && SAFE_VALUE.matcher(value).matches();
    }
}
