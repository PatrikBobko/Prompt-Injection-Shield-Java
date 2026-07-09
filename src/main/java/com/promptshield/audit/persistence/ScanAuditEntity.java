package com.promptshield.audit.persistence;

import com.promptshield.audit.ContentFingerprint;
import com.promptshield.audit.dto.ScanAuditSummary;
import com.promptshield.domain.ContentType;
import com.promptshield.domain.RiskReport;
import com.promptshield.domain.ScanRequest;
import com.promptshield.domain.Severity;
import com.promptshield.domain.SeverityCounts;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OrderColumn;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Immutable-after-write scan audit record.
 *
 * <p>This entity intentionally has no field for the submitted content. It
 * stores only a keyed HMAC-SHA-256 fingerprint plus report metadata and
 * privacy-safe finding summaries. In particular, no HTML/text, snippets, CSS locators,
 * human-readable reasons, or detector evidence are persisted.</p>
 */
@Entity
@Table(name = "scan_audit_records", indexes = {
        @Index(name = "idx_scan_audit_records_scanned_at", columnList = "scanned_at"),
        @Index(name = "idx_scan_audit_records_content_sha256", columnList = "content_sha256")
})
public class ScanAuditEntity {

    @Id
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "scanned_at", nullable = false, updatable = false)
    private Instant scannedAt;

    @Column(name = "content_sha256", nullable = false, updatable = false, length = 64)
    private String contentSha256;

    @Column(name = "subject", nullable = false, updatable = false, length = 255)
    private String subject;

    @Enumerated(EnumType.STRING)
    @Column(name = "content_type", nullable = false, updatable = false, length = 16)
    private ContentType contentType;

    @Column(name = "segments_scanned", nullable = false, updatable = false)
    private int segmentsScanned;

    @Enumerated(EnumType.STRING)
    @Column(name = "overall_severity", updatable = false, length = 16)
    private Severity overallSeverity;

    @Column(name = "risk_score", nullable = false, updatable = false)
    private int riskScore;

    @Column(name = "high_finding_count", nullable = false, updatable = false)
    private int highFindingCount;

    @Column(name = "medium_finding_count", nullable = false, updatable = false)
    private int mediumFindingCount;

    @Column(name = "low_finding_count", nullable = false, updatable = false)
    private int lowFindingCount;

    @Column(name = "finding_count", nullable = false, updatable = false)
    private int findingCount;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "scan_audit_findings", joinColumns = @JoinColumn(name = "audit_id"))
    @OrderColumn(name = "finding_position")
    private List<AuditFindingSnapshot> findings = new ArrayList<>();

    @Version
    @Column(name = "version", nullable = false)
    private long version;

    /** Required by JPA. */
    protected ScanAuditEntity() {
    }

    private ScanAuditEntity(ScanRequest request, RiskReport report, Instant scannedAt, String subject, String contentFingerprint) {
        Objects.requireNonNull(request, "request must not be null");
        Objects.requireNonNull(report, "report must not be null");

        SeverityCounts counts = Objects.requireNonNull(report.severityCounts(), "severity counts must not be null");
        List<AuditFindingSnapshot> persistedFindings = report.findings().stream()
                .map(AuditFindingSnapshot::from)
                .toList();
        if (counts.total() != persistedFindings.size()) {
            throw new IllegalArgumentException("severity count total must match the number of findings");
        }

        this.id = UUID.randomUUID();
        this.scannedAt = Objects.requireNonNull(scannedAt, "scannedAt must not be null");
        this.contentSha256 = requireFingerprint(contentFingerprint);
        this.subject = requireSubject(subject);
        this.contentType = Objects.requireNonNull(report.contentType(), "content type must not be null");
        this.segmentsScanned = report.segmentsScanned();
        this.overallSeverity = report.overallSeverity();
        this.riskScore = report.riskScore();
        this.highFindingCount = counts.high();
        this.mediumFindingCount = counts.medium();
        this.lowFindingCount = counts.low();
        this.findingCount = counts.total();
        this.findings = new ArrayList<>(persistedFindings);
    }

    /**
     * Produces a privacy-safe entity from a completed scan.
     */
    public static ScanAuditEntity from(ScanRequest request, RiskReport report, Instant scannedAt) {
        return from(request, report, scannedAt, "anonymous", ContentFingerprint.sha256(request.content()));
    }

    /** Produces a privacy-safe entity scoped to the authenticated subject. */
    public static ScanAuditEntity from(ScanRequest request, RiskReport report, Instant scannedAt, String subject) {
        return from(request, report, scannedAt, subject, ContentFingerprint.sha256(request.content()));
    }

    /** Produces an entity using the caller's keyed content fingerprint. */
    public static ScanAuditEntity from(ScanRequest request, RiskReport report, Instant scannedAt,
                                       String subject, String contentFingerprint) {
        return new ScanAuditEntity(request, report, scannedAt, subject, contentFingerprint);
    }

    public ScanAuditSummary toSummary() {
        return new ScanAuditSummary(
                id,
                scannedAt,
                contentSha256,
                contentType,
                segmentsScanned,
                overallSeverity,
                riskScore,
                new SeverityCounts(highFindingCount, mediumFindingCount, lowFindingCount, findingCount),
                findings.stream().map(AuditFindingSnapshot::toSummary).toList());
    }

    public UUID id() {
        return id;
    }

    public Instant scannedAt() {
        return scannedAt;
    }

    public String contentSha256() {
        return contentSha256;
    }

    public String subject() {
        return subject;
    }

    public ContentType contentType() {
        return contentType;
    }

    public int segmentsScanned() {
        return segmentsScanned;
    }

    public Severity overallSeverity() {
        return overallSeverity;

    }

    public int riskScore() {
        return riskScore;
    }

    public SeverityCounts severityCounts() {
        return new SeverityCounts(highFindingCount, mediumFindingCount, lowFindingCount, findingCount);
    }

    public List<AuditFindingSnapshot> findings() {
        return List.copyOf(findings);
    }

    private static String requireFingerprint(String contentFingerprint) {
        if (contentFingerprint == null || !contentFingerprint.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("content fingerprint must be a lowercase SHA-256-sized hexadecimal value");
        }
        return contentFingerprint;
    }
    private static String requireSubject(String subject) {
        if (subject == null || subject.isBlank() || subject.length() > 255) {
            throw new IllegalArgumentException("subject must be non-blank and no longer than 255 characters");
        }
        return subject;
    }
}
