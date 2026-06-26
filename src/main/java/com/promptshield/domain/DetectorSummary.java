package com.promptshield.domain;

/**
 * How many findings a given detector contributed to, for the report's
 * per-detector breakdown.
 */
public record DetectorSummary(String detectorId, DetectorCategory category, int findings) {
}
