package com.promptshield.detect.injection;

import java.util.regex.Pattern;

/**
 * One prompt-injection heuristic: a compiled regex plus metadata. Mirrors an
 * entry in the extension's {@code injection-patterns.js}.
 *
 * @param id      stable identifier, used in evidence and tests
 * @param pattern compiled matcher
 * @param label   human-readable description shown in findings
 * @param weight  rough confidence 1..3 (informational, as in the original)
 */
public record InjectionPattern(String id, Pattern pattern, String label, int weight) {

    static InjectionPattern of(String id, String regex, int flags, String label, int weight) {
        return new InjectionPattern(id, Pattern.compile(regex, flags), label, weight);
    }
}
