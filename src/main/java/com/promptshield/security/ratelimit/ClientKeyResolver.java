package com.promptshield.security.ratelimit;

import jakarta.servlet.http.HttpServletRequest;

/** Resolves a rate-limit identity without persisting or logging the raw value. */
@FunctionalInterface
public interface ClientKeyResolver {

    String resolve(HttpServletRequest request);

    /**
     * Uses the direct peer address. This is safe by default and intentionally
     * does not trust X-Forwarded-For, which clients can forge unless a trusted
     * reverse proxy strips and rewrites it.
     */
    static ClientKeyResolver remoteAddress() {
        return request -> {
            String address = request.getRemoteAddr();
            return address == null || address.isBlank() ? "unknown" : address;
        };
    }
}
