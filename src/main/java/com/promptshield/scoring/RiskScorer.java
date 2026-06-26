package com.promptshield.scoring;

import com.promptshield.domain.Severity;
import com.promptshield.domain.SeverityCounts;
import org.springframework.stereotype.Component;

/**
 * Aggregates per-finding severities into a single report-level view: an overall
 * severity (the worst present) and a 0..100 risk score.
 *
 * <p>The original extension only reported per-severity counts; the numeric score
 * is a thin, deliberately simple aggregation layered on top for callers that want
 * one comparable number. Weights are tuned so that a single HIGH dominates and
 * the score saturates at 100.
 */
@Component
public class RiskScorer {

    static final int HIGH_WEIGHT = 40;
    static final int MEDIUM_WEIGHT = 15;
    static final int LOW_WEIGHT = 5;
    static final int MAX_SCORE = 100;

    /** Worst severity present, or {@code null} when there are no findings. */
    public Severity overall(SeverityCounts counts) {
        if (counts.high() > 0) {
            return Severity.HIGH;
        }
        if (counts.medium() > 0) {
            return Severity.MEDIUM;
        }
        if (counts.low() > 0) {
            return Severity.LOW;
        }
        return null;
    }

    /** Aggregate risk in 0..100. */
    public int score(SeverityCounts counts) {
        long raw = (long) counts.high() * HIGH_WEIGHT
                + (long) counts.medium() * MEDIUM_WEIGHT
                + (long) counts.low() * LOW_WEIGHT;
        return (int) Math.min(MAX_SCORE, raw);
    }
}
