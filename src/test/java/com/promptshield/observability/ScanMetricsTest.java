package com.promptshield.observability;

import com.promptshield.domain.Channel;
import com.promptshield.domain.ContentType;
import com.promptshield.domain.Finding;
import com.promptshield.domain.RiskReport;
import com.promptshield.domain.Severity;
import com.promptshield.domain.SeverityCounts;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ScanMetricsTest {

    @Test
    void capturesSuccessfulAndFailedScansWithoutRecordingContent() {
        AtomicLong clock = new AtomicLong();
        ScanMetrics metrics = new ScanMetrics(clock::get);

        ScanObservation success = metrics.startObservation();
        clock.addAndGet(Duration.ofMillis(12).toNanos());
        success.succeed(highRiskReport());
        success.succeed(highRiskReport()); // terminal observations are idempotent

        ScanObservation failure = metrics.startObservation();
        clock.addAndGet(Duration.ofMillis(8).toNanos());
        failure.close();

        ScanMetricsSnapshot snapshot = metrics.snapshot();
        assertEquals(1, snapshot.successfulScans());
        assertEquals(1, snapshot.failedScans());
        assertEquals(0, snapshot.cleanScans());
        assertEquals(1, snapshot.findings());
        assertEquals(1L, snapshot.findingsBySeverity().get(Severity.HIGH));
        assertEquals(Duration.ofMillis(20), snapshot.totalDuration());
        assertEquals(Duration.ofMillis(12), snapshot.maxDuration());
        assertEquals(Duration.ofMillis(10), snapshot.averageDuration());
    }

    private static RiskReport highRiskReport() {
        Finding finding = new Finding(0, Severity.HIGH, Channel.HTML_COMMENT, null, "", List.of(), List.of(), List.of());
        return new RiskReport(
                ContentType.HTML,
                1,
                Severity.HIGH,
                40,
                new SeverityCounts(1, 0, 0, 1),
                List.of(),
                List.of(finding));
    }
}
