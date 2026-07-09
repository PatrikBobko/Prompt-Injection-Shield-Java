package com.promptshield.api;

import com.promptshield.audit.CurrentAuditSubject;
import com.promptshield.audit.dto.ScanAuditSummary;
import com.promptshield.audit.service.AuditHistoryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springdoc.core.annotations.ParameterObject;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import com.promptshield.domain.RiskReport;
import com.promptshield.domain.ScanRequest;
import com.promptshield.service.DetectionService;
import jakarta.validation.Valid;
import org.springframework.data.web.PageableDefault;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * REST entry points for the scanner.
 */
@Tag(name = "Scanning", description = "Prompt-injection analysis and privacy-safe audit history")
@RestController
@RequestMapping("/api/v1")
public class ScanController {

    private final DetectionService detectionService;
    private final AuditHistoryService auditHistoryService;
    private final CurrentAuditSubject currentAuditSubject;

    public ScanController(DetectionService detectionService,
                          AuditHistoryService auditHistoryService,
                          CurrentAuditSubject currentAuditSubject) {
        this.detectionService = detectionService;
        this.auditHistoryService = auditHistoryService;
        this.currentAuditSubject = currentAuditSubject;
    }

    /**
     * Analyse HTML or text and return a structured risk report.
     */
    @PostMapping("/scan")
    @Operation(summary = "Scan HTML or text for hidden prompt-injection payloads")
    public RiskReport scan(@Valid @RequestBody ScanRequest request) {
        RiskReport report = detectionService.scan(request);
        auditHistoryService.record(request, report, currentAuditSubject.subject());
        return report;
    }

    /** Returns audit entries belonging only to the current authenticated subject. */
    @GetMapping("/scans")
    @Operation(summary = "List the caller's privacy-safe scan audit history")
    public Page<ScanAuditSummary> scans(
            @ParameterObject
            @PageableDefault(size = 20, sort = "scannedAt", direction = Sort.Direction.DESC) Pageable pageable) {
        return auditHistoryService.recent(currentAuditSubject.subject(), pageable);
    }

    /**
     * Liveness check.
     */
    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "UP");
    }
}
