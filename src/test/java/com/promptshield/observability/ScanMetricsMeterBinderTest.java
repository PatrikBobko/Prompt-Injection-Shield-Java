package com.promptshield.observability;

import com.promptshield.domain.ContentType;
import com.promptshield.domain.RiskReport;
import com.promptshield.domain.SeverityCounts;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ScanMetricsMeterBinderTest {

    @Test
    void exposesPrivacySafeOutcomeAndLatencyGauges() {
        AtomicLong clock = new AtomicLong();
        ScanMetrics metrics = new ScanMetrics(clock::get);
        try (ScanObservation observation = metrics.startObservation()) {
            clock.addAndGet(Duration.ofMillis(3).toNanos());
            observation.succeed(cleanReport());
        }

        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        try {
            new ScanMetricsMeterBinder(metrics).bindTo(registry);

            assertEquals(1.0d, registry.get("promptshield.scan.successful").gauge().value());
            assertEquals(1.0d, registry.get("promptshield.scan.clean").gauge().value());
            assertEquals(3_000_000.0d, registry.get("promptshield.scan.duration.max").gauge().value());
            assertEquals(0.0d, registry.get("promptshield.scan.findings.by_severity")
                    .tag("severity", "high").gauge().value());
        } finally {
            registry.close();
        }
    }

    private static RiskReport cleanReport() {
        return new RiskReport(
                ContentType.TEXT,
                1,
                null,
                0,
                new SeverityCounts(0, 0, 0, 0),
                List.of(),
                List.of());
    }
}
