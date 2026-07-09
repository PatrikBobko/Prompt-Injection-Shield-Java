package com.promptshield.audit.dto;

import com.promptshield.domain.ContentType;
import com.promptshield.domain.Severity;
import com.promptshield.domain.SeverityCounts;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * API-facing audit-history entry that contains scan metadata only.
 *
 * <p>The original request body, source snippets, CSS locators and evidence are
 * never included. Those values can be sensitive even when a full HTML document
 * is not retained.</p>
 */
public record ScanAuditSummary(
        UUID id,
        Instant scannedAt,
        String contentSha256,
        ContentType contentType,
        int segmentsScanned,
        Severity overallSeverity,
        int riskScore,
        SeverityCounts severityCounts,
        List<AuditFindingSummary> findings
) {
    public ScanAuditSummary {
        findings = List.copyOf(findings);
    }
}
