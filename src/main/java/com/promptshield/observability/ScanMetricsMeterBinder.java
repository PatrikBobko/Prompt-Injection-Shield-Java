package com.promptshield.observability;

import com.promptshield.domain.Severity;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.MeterBinder;

import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * Exposes {@link ScanMetrics} to Micrometer without ever adding request content
 * or client identifiers as metric tags. Register this binder as a Spring bean
 * after creating the corresponding {@link ScanMetrics} singleton.
 */
public final class ScanMetricsMeterBinder implements MeterBinder {

    private static final String METRIC_PREFIX = "promptshield.scan";

    private final ScanMetrics scanMetrics;

    public ScanMetricsMeterBinder(ScanMetrics scanMetrics) {
        this.scanMetrics = Objects.requireNonNull(scanMetrics, "scanMetrics must not be null");
    }

    @Override
    public void bindTo(MeterRegistry registry) {
        Gauge.builder(METRIC_PREFIX + ".successful", scanMetrics,
                        metrics -> metrics.snapshot().successfulScans())
                .description("Completed scans that returned a report")
                .register(registry);
        Gauge.builder(METRIC_PREFIX + ".failed", scanMetrics,
                        metrics -> metrics.snapshot().failedScans())
                .description("Scans that terminated without a report")
                .register(registry);
        Gauge.builder(METRIC_PREFIX + ".clean", scanMetrics,
                        metrics -> metrics.snapshot().cleanScans())
                .description("Completed scans with no findings")
                .register(registry);
        Gauge.builder(METRIC_PREFIX + ".findings", scanMetrics,
                        metrics -> metrics.snapshot().findings())
                .description("Findings produced across completed scans")
                .register(registry);

        Gauge.builder(METRIC_PREFIX + ".duration.total", scanMetrics,
                        metrics -> metrics.snapshot().totalDuration().toNanos())
                .description("Total scan time")
                .baseUnit("nanoseconds")
                .register(registry);
        Gauge.builder(METRIC_PREFIX + ".duration.max", scanMetrics,
                        metrics -> metrics.snapshot().maxDuration().toNanos())
                .description("Longest observed scan time")
                .baseUnit("nanoseconds")
                .register(registry);

        for (Severity severity : Severity.values()) {
            Gauge.builder(METRIC_PREFIX + ".findings.by_severity", scanMetrics,
                            metrics -> metrics.snapshot().findingsBySeverity().get(severity))
                    .tag("severity", severity.name().toLowerCase())
                    .description("Findings grouped by severity")
                    .register(registry);
        }
    }
}
