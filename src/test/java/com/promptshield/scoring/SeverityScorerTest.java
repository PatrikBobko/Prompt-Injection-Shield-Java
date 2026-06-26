package com.promptshield.scoring;

import com.promptshield.domain.Severity;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class SeverityScorerTest {

    private final SeverityScorer scorer = new SeverityScorer();

    @Test
    void injectionPlusHiddenIsHigh() {
        assertThat(scorer.score(true, true, false)).contains(Severity.HIGH);
    }

    @Test
    void stegoAloneIsMedium() {
        assertThat(scorer.score(false, false, true)).contains(Severity.MEDIUM);
    }

    @Test
    void stegoWithInjectionIsHigh() {
        assertThat(scorer.score(false, true, true)).contains(Severity.HIGH);
    }

    @Test
    void visibleInjectionIsLow() {
        assertThat(scorer.score(false, true, false)).contains(Severity.LOW);
    }

    @Test
    void hiddenAloneIsSuppressed() {
        assertThat(scorer.score(true, false, false)).isEmpty();
    }

    @Test
    void nothingIsSuppressed() {
        assertThat(scorer.score(false, false, false)).isEmpty();
    }

    @Test
    void stegoOutranksHidingWhenNoInjection() {
        // hidden + stego but no injection: stego wins => MEDIUM, not suppressed.
        assertThat(scorer.score(true, false, true)).contains(Severity.MEDIUM);
    }

    @Test
    void emptyOptionalNeverThrows() {
        Optional<Severity> result = scorer.score(true, false, false);
        assertThat(result).isNotNull();
    }
}
