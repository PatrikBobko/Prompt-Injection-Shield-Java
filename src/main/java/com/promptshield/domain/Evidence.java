package com.promptshield.domain;

/**
 * A located piece of proof backing a finding: a regex match, a run of invisible
 * code points, a hiding style, etc. Offsets are indices into the owning
 * segment's text (UTF-16 code units, so they line up with Java {@code String}
 * indexing), or {@code null} when the evidence is not tied to a position.
 *
 * @param kind    short machine-readable tag, e.g. {@code "pattern:ignore-previous"},
 *                {@code "zero-width"}, {@code "tags-payload"}, {@code "hidden-style"}
 * @param snippet the offending text (may be empty for invisible characters)
 * @param offset  start index into the segment text, or {@code null}
 * @param length  length in code units, or {@code null}
 * @param decoded recovered payload for steganography (e.g. decoded Tags block), else {@code null}
 */
public record Evidence(
        String kind,
        String snippet,
        Integer offset,
        Integer length,
        String decoded
) {
    public static Evidence at(String kind, String snippet, int offset, int length) {
        return new Evidence(kind, snippet, offset, length, null);
    }

    public static Evidence note(String kind, String snippet) {
        return new Evidence(kind, snippet, null, null, null);
    }

    public Evidence withDecoded(String decodedPayload) {
        return new Evidence(kind, snippet, offset, length, decodedPayload);
    }
}
