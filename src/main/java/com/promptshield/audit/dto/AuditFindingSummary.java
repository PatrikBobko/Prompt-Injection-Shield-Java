package com.promptshield.audit.dto;

import com.promptshield.domain.Channel;
import com.promptshield.domain.Severity;

import java.util.List;

/**
 * Privacy-safe representation of a persisted finding.
 *
 * <p>It deliberately excludes the source locator, snippet, reasons and
 * evidence because any of those can contain user-submitted content.</p>
 */
public record AuditFindingSummary(
        int findingId,
        Severity severity,
        Channel channel,
        List<String> detectors
) {
    public AuditFindingSummary {
        detectors = List.copyOf(detectors);
    }
}
