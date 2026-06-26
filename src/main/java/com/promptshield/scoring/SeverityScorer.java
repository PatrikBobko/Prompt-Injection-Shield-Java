package com.promptshield.scoring;

import com.promptshield.domain.Severity;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * The severity matrix, ported verbatim from the extension's {@code score.js}.
 *
 * <pre>
 *   injection AND hidden        -> HIGH
 *   stego                       -> HIGH if also injection, else MEDIUM
 *   injection (visible)         -> LOW
 *   hidden only (no inj/stego)  -> nothing (suppressed)
 *   nothing                     -> nothing
 * </pre>
 *
 * <p>Hiding never produces a finding by itself: plain hidden text is ubiquitous
 * on real pages and would bury genuine threats under false positives.
 */
@Component
public class SeverityScorer {

    /**
     * @param hidden    the text is visually hidden or in a non-rendered channel
     * @param injection the text contains prompt-injection phrasing
     * @param stego     the text contains invisible/steganographic Unicode
     * @return the severity to report, or empty when there is nothing to report
     */
    public Optional<Severity> score(boolean hidden, boolean injection, boolean stego) {
        if (injection && hidden) {
            return Optional.of(Severity.HIGH);
        }
        if (stego) {
            return Optional.of(injection ? Severity.HIGH : Severity.MEDIUM);
        }
        if (injection) {
            return Optional.of(Severity.LOW);
        }
        return Optional.empty();
    }
}
