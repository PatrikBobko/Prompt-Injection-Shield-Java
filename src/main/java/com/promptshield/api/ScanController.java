package com.promptshield.api;

import com.promptshield.domain.RiskReport;
import com.promptshield.domain.ScanRequest;
import com.promptshield.service.DetectionService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * REST entry points for the scanner.
 */
@RestController
@RequestMapping("/api/v1")
public class ScanController {

    private final DetectionService detectionService;

    public ScanController(DetectionService detectionService) {
        this.detectionService = detectionService;
    }

    /**
     * Analyse HTML or text and return a structured risk report.
     */
    @PostMapping("/scan")
    public RiskReport scan(@Valid @RequestBody ScanRequest request) {
        return detectionService.scan(request);
    }

    /**
     * Liveness check.
     */
    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "UP");
    }
}
