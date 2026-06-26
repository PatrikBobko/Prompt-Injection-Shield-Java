package com.promptshield.detect.injection;

import com.promptshield.detect.Detector;
import com.promptshield.detect.DetectorResult;
import com.promptshield.detect.Segment;
import com.promptshield.domain.DetectorCategory;
import com.promptshield.domain.Evidence;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;

/**
 * Runs the prompt-injection heuristics over a segment's text. Ported from
 * {@code injection.js}: each pattern fires at most once (first match), and a hit
 * contributes the pattern's label as a reason plus located evidence.
 */
@Component
public class InjectionPatternDetector implements Detector {

    public static final String ID = "injection";

    private final List<InjectionPattern> patterns;

    public InjectionPatternDetector() {
        this(InjectionPatterns.DEFAULTS);
    }

    /** Package/test constructor allowing a custom rule set. */
    InjectionPatternDetector(List<InjectionPattern> patterns) {
        this.patterns = List.copyOf(patterns);
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public DetectorCategory category() {
        return DetectorCategory.INJECTION;
    }

    @Override
    public Optional<DetectorResult> inspect(Segment segment) {
        String text = segment.text();
        if (text == null || text.isEmpty()) {
            return Optional.empty();
        }

        List<String> reasons = new ArrayList<>();
        List<Evidence> evidence = new ArrayList<>();

        for (InjectionPattern p : patterns) {
            Matcher m = p.pattern().matcher(text);
            if (m.find()) {
                reasons.add(p.label());
                String match = m.group().trim();
                evidence.add(Evidence.at("pattern:" + p.id(), match, m.start(), m.end() - m.start()));
            }
        }

        if (reasons.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new DetectorResult(ID, DetectorCategory.INJECTION, reasons, evidence));
    }
}
