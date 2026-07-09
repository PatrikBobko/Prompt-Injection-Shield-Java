package com.promptshield.observability;

import com.promptshield.domain.RiskReport;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Measures one scan attempt. Unfinished observations become failed attempts
 * when closed, which makes it safe to use in a try-with-resources block.
 */
public final class ScanObservation implements AutoCloseable {

    private final ScanMetrics metrics;
    private final long startedAtNanos;
    private final AtomicBoolean completed = new AtomicBoolean();

    ScanObservation(ScanMetrics metrics, long startedAtNanos) {
        this.metrics = metrics;
        this.startedAtNanos = startedAtNanos;
    }

    /** Records a successful scan exactly once. */
    public void succeed(RiskReport report) {
        Objects.requireNonNull(report, "report must not be null");
        if (completed.compareAndSet(false, true)) {
            metrics.recordSuccess(report, elapsedNanos());
        }
    }

    /** Records a failed scan exactly once. */
    public void fail() {
        if (completed.compareAndSet(false, true)) {
            metrics.recordFailure(elapsedNanos());
        }
    }

    /**
     * Treat an observation that exits exceptionally or was forgotten by the
     * caller as a failed scan.
     */
    @Override
    public void close() {
        fail();
    }

    private long elapsedNanos() {
        return Math.max(0L, metrics.nowNanos() - startedAtNanos);
    }
}
