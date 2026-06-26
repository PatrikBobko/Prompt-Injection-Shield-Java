package com.promptshield.scoring;

import com.promptshield.domain.Severity;
import com.promptshield.domain.SeverityCounts;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RiskScorerTest {

    private final RiskScorer scorer = new RiskScorer();

    @Test
    void overallIsNullWhenClean() {
        assertThat(scorer.overall(new SeverityCounts(0, 0, 0, 0))).isNull();
    }

    @Test
    void overallPicksWorstSeverity() {
        assertThat(scorer.overall(new SeverityCounts(1, 5, 9, 15))).isEqualTo(Severity.HIGH);
        assertThat(scorer.overall(new SeverityCounts(0, 2, 9, 11))).isEqualTo(Severity.MEDIUM);
        assertThat(scorer.overall(new SeverityCounts(0, 0, 3, 3))).isEqualTo(Severity.LOW);
    }

    @Test
    void scoreIsZeroWhenClean() {
        assertThat(scorer.score(new SeverityCounts(0, 0, 0, 0))).isZero();
    }

    @Test
    void scoreWeightsSeverities() {
        assertThat(scorer.score(new SeverityCounts(0, 0, 1, 1))).isEqualTo(5);
        assertThat(scorer.score(new SeverityCounts(0, 1, 0, 1))).isEqualTo(15);
        assertThat(scorer.score(new SeverityCounts(1, 0, 0, 1))).isEqualTo(40);
        assertThat(scorer.score(new SeverityCounts(1, 1, 1, 3))).isEqualTo(60);
    }

    @Test
    void scoreSaturatesAt100() {
        assertThat(scorer.score(new SeverityCounts(10, 0, 0, 10))).isEqualTo(100);
    }
}
