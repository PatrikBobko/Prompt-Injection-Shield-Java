package com.promptshield.domain;

/**
 * Risk severity of a finding. Ranks mirror the original extension's
 * {@code SEVERITY_RANK} (higher = worse) so sorting and aggregation behave the
 * same way.
 */
public enum Severity {
    LOW(1),
    MEDIUM(2),
    HIGH(3);

    private final int rank;

    Severity(int rank) {
        this.rank = rank;
    }

    public int rank() {
        return rank;
    }
}
