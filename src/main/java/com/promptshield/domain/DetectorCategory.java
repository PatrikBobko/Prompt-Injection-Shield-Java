package com.promptshield.domain;

/**
 * The role a detector's signal plays in scoring.
 *
 * <p>This is the crux of the original extension's design: hiding on its own is
 * never a finding (collapsed menus, screen-reader-only text and low-contrast UI
 * are everywhere), so {@link #HIDING} signals only <em>amplify</em> the severity
 * of an {@link #INJECTION} or {@link #STEGO} signal. The severity matrix lives in
 * the scorer, not in the detectors.
 */
public enum DetectorCategory {
    /** Prompt-injection phrasing in the text. */
    INJECTION,
    /** Invisible / steganographic Unicode (zero-width, bidi, Tags block). */
    STEGO,
    /** The text is visually hidden or travels in a non-rendered channel. */
    HIDING
}
