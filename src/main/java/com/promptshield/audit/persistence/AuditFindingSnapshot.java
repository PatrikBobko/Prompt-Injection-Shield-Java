package com.promptshield.audit.persistence;

import com.promptshield.audit.dto.AuditFindingSummary;
import com.promptshield.domain.Channel;
import com.promptshield.domain.Finding;
import com.promptshield.domain.Severity;
import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;

import java.util.List;
import java.util.Objects;

/**
 * A persistence-safe subset of a scan finding.
 *
 * <p>It contains enough information to investigate detector behavior, while
 * omitting all submitted-text-derived values (snippet, locator, reasons and
 * evidence). Detector ids are application-defined identifiers, not user input.</p>
 */
@Embeddable
public class AuditFindingSnapshot {

    private static final String DETECTOR_SEPARATOR = ",";

    @Column(name = "finding_id", nullable = false, updatable = false)
    private int findingId;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false, updatable = false, length = 16)
    private Severity severity;

    @Enumerated(EnumType.STRING)
    @Column(name = "channel", nullable = false, updatable = false, length = 32)
    private Channel channel;

    @Column(name = "detector_ids", nullable = false, updatable = false, length = 512)
    private String detectorIds;

    /** Required by JPA. */
    protected AuditFindingSnapshot() {
    }

    private AuditFindingSnapshot(int findingId, Severity severity, Channel channel, List<String> detectorIds) {
        this.findingId = findingId;
        this.severity = Objects.requireNonNull(severity, "severity must not be null");
        this.channel = Objects.requireNonNull(channel, "channel must not be null");
        this.detectorIds = encodeDetectorIds(detectorIds);
    }

    static AuditFindingSnapshot from(Finding finding) {
        Objects.requireNonNull(finding, "finding must not be null");
        return new AuditFindingSnapshot(
                finding.id(), finding.severity(), finding.channel(), finding.detectors());
    }

    AuditFindingSummary toSummary() {
        return new AuditFindingSummary(findingId, severity, channel, detectorIds());
    }

    public int findingId() {
        return findingId;
    }

    public Severity severity() {
        return severity;
    }

    public Channel channel() {
        return channel;
    }

    public List<String> detectorIds() {
        if (detectorIds.isEmpty()) {
            return List.of();
        }
        return List.of(detectorIds.split(DETECTOR_SEPARATOR, -1));
    }

    private static String encodeDetectorIds(List<String> detectorIds) {
        Objects.requireNonNull(detectorIds, "detector ids must not be null");
        for (String detectorId : detectorIds) {
            if (detectorId == null || detectorId.isBlank() || detectorId.contains(DETECTOR_SEPARATOR)) {
                throw new IllegalArgumentException("detector ids must be non-blank and must not contain commas");
            }
        }
        return String.join(DETECTOR_SEPARATOR, detectorIds);
    }
}
