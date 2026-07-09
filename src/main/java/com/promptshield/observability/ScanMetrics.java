package com.promptshield.observability;

import com.promptshield.domain.RiskReport;
import com.promptshield.domain.Severity;

import java.time.Duration;
import java.util.EnumMap;
import java.util.concurrent.atomic.LongAccumulator;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.LongSupplier;

/**
 * Thread-safe, in-process counters for scan outcomes and latency.
 *
 * <p>This class is deliberately independent of any metrics vendor. It can be
 * used as a small local health signal today and adapted to Micrometer counters
 * and timers when Actuator is enabled. Submitted content is never recorded.</p>
 */
public final class ScanMetrics {

    private final LongSupplier nanoClock;
    private final LongAdder successfulScans = new LongAdder();
    private final LongAdder failedScans = new LongAdder();
    private final LongAdder cleanScans = new LongAdder();
    private final LongAdder findings = new LongAdder();
    private final LongAdder totalDurationNanos = new LongAdder();
    private final LongAccumulator maxDurationNanos = new LongAccumulator(Long::max, 0L);
    private final EnumMap<Severity, LongAdder> findingsBySeverity = new EnumMap<>(Severity.class);

    /** Creates metrics that use Java's monotonic clock for duration measurement. */
    public ScanMetrics() {
        this(System::nanoTime);
    }

    ScanMetrics(LongSupplier nanoClock) {
        this.nanoClock = nanoClock;
        for (Severity severity : Severity.values()) {
            findingsBySeverity.put(severity, new LongAdder());
        }
    }

    /** Starts one scan observation. Call {@link ScanObservation#succeed(RiskReport)} on success. */
    public ScanObservation startObservation() {
        return new ScanObservation(this, nanoClock.getAsLong());
    }

    /** Creates an immutable, privacy-safe snapshot suitable for an actuator contributor or dashboard. */
    public ScanMetricsSnapshot snapshot() {
        EnumMap<Severity, Long> severityCounts = new EnumMap<>(Severity.class);
        for (Severity severity : Severity.values()) {
            severityCounts.put(severity, findingsBySeverity.get(severity).sum());
        }
        return new ScanMetricsSnapshot(
                successfulScans.sum(),
                failedScans.sum(),
                cleanScans.sum(),
                findings.sum(),
                severityCounts,
                Duration.ofNanos(totalDurationNanos.sum()),
                Duration.ofNanos(maxDurationNanos.get()));
    }

    long nowNanos() {
        return nanoClock.getAsLong();
    }

    void recordSuccess(RiskReport report, long elapsedNanos) {
        successfulScans.increment();
        recordDuration(elapsedNanos);

        if (report.clean()) {
            cleanScans.increment();
        }
        findings.add(report.findings().size());
        report.findings().forEach(finding -> findingsBySeverity.get(finding.severity()).increment());
    }

    void recordFailure(long elapsedNanos) {
        failedScans.increment();
        recordDuration(elapsedNanos);
    }

    private void recordDuration(long elapsedNanos) {
        long nonNegativeElapsed = Math.max(0L, elapsedNanos);
        totalDurationNanos.add(nonNegativeElapsed);
        maxDurationNanos.accumulate(nonNegativeElapsed);
    }
}
