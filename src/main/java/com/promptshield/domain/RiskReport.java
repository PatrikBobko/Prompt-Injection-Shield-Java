package com.promptshield.domain;

import java.util.List;

/**
 * The structured risk report returned by the API.
 *
 * @param contentType       how the input was interpreted
 * @param segmentsScanned   number of text segments examined
 * @param overallSeverity   highest severity present, or {@code null} when clean
 * @param riskScore         aggregate 0..100 score (see RiskScorer)
 * @param severityCounts    per-severity tally
 * @param detectorBreakdown how many findings each detector contributed to
 * @param findings          the individual findings
 */
public record RiskReport(
        ContentType contentType,
        int segmentsScanned,
        Severity overallSeverity,
        int riskScore,
        SeverityCounts severityCounts,
        List<DetectorSummary> detectorBreakdown,
        List<Finding> findings
) {
    public boolean clean() {
        return findings.isEmpty();
    }
}
