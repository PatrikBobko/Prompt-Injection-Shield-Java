package com.promptshield.detect.injection;

import java.util.List;
import java.util.regex.Pattern;

/**
 * The editable rule list, ported verbatim from {@code injection-patterns.js}.
 * The bounded gaps ({@code [^.\n]{0,40}} etc.) are deliberate: they keep a match
 * within a single sentence. Preserve the magic numbers and alternations exactly.
 */
public final class InjectionPatterns {

    private static final int I = Pattern.CASE_INSENSITIVE;
    private static final int IM = Pattern.CASE_INSENSITIVE | Pattern.MULTILINE;

    /** The default, ordered rule set. */
    public static final List<InjectionPattern> DEFAULTS = List.of(
            InjectionPattern.of(
                    "ignore-previous",
                    "\\b(ignore|disregard|forget)\\b[^.\\n]{0,40}\\b(previous|prior|above|earlier|all)\\b[^.\\n]{0,20}\\b(instruction|prompt|message|context|rule)s?\\b",
                    I,
                    "asks the AI to ignore previous instructions",
                    3),
            InjectionPattern.of(
                    "new-instructions",
                    "\\b(new|updated|revised|the following)\\b[^.\\n]{0,20}\\b(instruction|directive|rule|task)s?\\b",
                    I,
                    "introduces \"new instructions\"",
                    2),
            InjectionPattern.of(
                    "you-are-now",
                    "\\byou\\s+are\\s+(now|a|an|hereby)\\b",
                    I,
                    "attempts to reassign the AI's role (\"you are now...\")",
                    2),
            InjectionPattern.of(
                    "system-prompt",
                    "\\bsystem\\s*(prompt|message|instruction)s?\\b",
                    I,
                    "references the system prompt",
                    2),
            InjectionPattern.of(
                    "as-an-ai",
                    "\\bas\\s+an?\\s+(ai|assistant|language\\s+model|llm)\\b",
                    I,
                    "addresses the reader as an AI",
                    1),
            InjectionPattern.of(
                    "assistant-turn",
                    "^\\s*(assistant|ai|system|user)\\s*:",
                    IM,
                    "fakes a chat turn (\"assistant:\")",
                    2),
            InjectionPattern.of(
                    "do-not-tell",
                    "\\bdo\\s+not\\s+(tell|inform|reveal|mention|disclose)\\b[^.\\n]{0,30}\\b(user|human|anyone)\\b",
                    I,
                    "tells the AI to hide something from the user",
                    3),
            InjectionPattern.of(
                    "role-tag",
                    "</?\\s*(system|user|assistant|instructions?|im_start|im_end)\\s*>|\\[/?\\s*(INST|SYS)\\s*\\]",
                    I,
                    "contains chat/role markup (<system>, [INST]...)",
                    3),
            InjectionPattern.of(
                    "override-directive",
                    "\\b(override|bypass|jailbreak|developer\\s+mode)\\b",
                    I,
                    "uses override/jailbreak language",
                    2),
            InjectionPattern.of(
                    "imperative-to-ai",
                    "\\b(your\\s+(new\\s+)?(task|goal|instruction|objective)\\s+is)\\b",
                    I,
                    "states a task/goal directed at the AI",
                    2));

    private InjectionPatterns() {
    }
}
