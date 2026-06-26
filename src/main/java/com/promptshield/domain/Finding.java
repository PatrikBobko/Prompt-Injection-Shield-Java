package com.promptshield.domain;

import java.util.List;

/**
 * A single reportable problem found in one segment of the input. Severity is
 * assigned by the scorer from the categories of the detectors that fired; a
 * segment that produced only suppressed (hiding-only) signals never becomes a
 * Finding.
 *
 * @param id        stable index within a single report
 * @param severity  HIGH / MEDIUM / LOW
 * @param channel   where the offending text lives
 * @param locator   a human-usable pointer to the source node (CSS-path-like), or {@code null}
 * @param snippet   short, whitespace-collapsed excerpt of the text
 * @param reasons   human-readable explanations (hiding + stego + injection)
 * @param detectors ids of the detectors that contributed
 * @param evidence  located proof items
 */
public record Finding(
        int id,
        Severity severity,
        Channel channel,
        String locator,
        String snippet,
        List<String> reasons,
        List<String> detectors,
        List<Evidence> evidence
) {
}
