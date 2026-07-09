package com.promptshield.audit.persistence;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

/**
 * Audit-history storage ordered newest-first for user-facing history views.
 */
public interface ScanAuditRepository extends JpaRepository<ScanAuditEntity, UUID> {

    Page<ScanAuditEntity> findAllBySubjectOrderByScannedAtDesc(String subject, Pageable pageable);

    Page<ScanAuditEntity> findAllByOrderByScannedAtDesc(Pageable pageable);
}
