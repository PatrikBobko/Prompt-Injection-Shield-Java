package com.promptshield.observability;

import com.promptshield.domain.Severity;

import java.time.Duration;
import java.util.Map;

/**
 * Immutable, privacy-safe view of scanner activity. It intentionally contains
 * no submitted content, snippets, locators or client identifiers.
 */
public record ScanMetricsSnapshot(
        long successfulScans,
        long failedScans,
        long cleanScans,
        long findings,
        Map<Severity, Long> findingsBySeverity,
        Duration totalDuration,
        Duration maxDuration
) {

    public ScanMetricsSnapshot {
        findingsBySeverity = Map.copyOf(findingsBySeverity);
    }

    /** Total scans that have reached a terminal success or failure state. */
    public long completedScans() {
        return successfulScans + failedScans;
    }

    /** Average duration across all terminal scan attempts, or zero before data exists. */
    public Duration averageDuration() {
        long completed = completedScans();
        return completed == 0 ? Duration.ZERO : totalDuration.dividedBy(completed);
    }
}
