package com.promptshield.detect;

import com.promptshield.domain.DetectorCategory;
import com.promptshield.domain.Evidence;

import java.util.List;

/**
 * What a detector reports for a single segment when it fires: the role of the
 * signal, human-readable reasons, and located evidence. A detector that finds
 * nothing returns {@code Optional.empty()} instead of an empty result.
 */
public record DetectorResult(
        String detectorId,
        DetectorCategory category,
        List<String> reasons,
        List<Evidence> evidence
) {
    public DetectorResult {
        reasons = List.copyOf(reasons);
        evidence = List.copyOf(evidence);
    }
}
