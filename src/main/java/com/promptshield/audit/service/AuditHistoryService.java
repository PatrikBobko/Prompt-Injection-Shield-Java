package com.promptshield.audit.service;

import com.promptshield.audit.ContentFingerprintService;
import com.promptshield.audit.dto.ScanAuditSummary;
import com.promptshield.audit.persistence.ScanAuditEntity;
import com.promptshield.audit.persistence.ScanAuditRepository;
import com.promptshield.domain.RiskReport;
import com.promptshield.domain.ScanRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * Records and retrieves privacy-safe scan history.
 *
 * <p>The service is deliberately separate from scan execution: the API layer
 * should call {@link #record(ScanRequest, RiskReport)} only after a successful
 * detection run has produced its report.</p>
 */
@Service
public class AuditHistoryService {

    private final ScanAuditRepository auditRepository;
    private final ContentFingerprintService contentFingerprintService;

    public AuditHistoryService(ScanAuditRepository auditRepository,
                               ContentFingerprintService contentFingerprintService) {
        this.auditRepository = auditRepository;
        this.contentFingerprintService = contentFingerprintService;
    }

    @Transactional
    public ScanAuditSummary record(ScanRequest request, RiskReport report) {
        return record(request, report, "anonymous");
    }

    @Transactional
    public ScanAuditSummary record(ScanRequest request, RiskReport report, String subject) {
        ScanAuditEntity audit = ScanAuditEntity.from(request, report, Instant.now(), subject,
                contentFingerprintService.fingerprint(request.content()));
        return auditRepository.save(audit).toSummary();
    }

    @Transactional(readOnly = true)
    public Page<ScanAuditSummary> recent(Pageable pageable) {
        return recent("anonymous", pageable);
    }

    @Transactional(readOnly = true)
    public Page<ScanAuditSummary> recent(String subject, Pageable pageable) {
        return auditRepository.findAllBySubjectOrderByScannedAtDesc(subject, pageable)
                .map(ScanAuditEntity::toSummary);
    }
}
