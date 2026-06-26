package com.promptshield.detect;

import com.promptshield.detect.css.StyleSnapshot;
import com.promptshield.domain.Channel;

/**
 * One unit of analysed text plus its provenance. Produced by the extractor and
 * consumed by every {@link Detector}. Detectors never see the DOM &mdash; only
 * this flat record &mdash; which keeps them pure and unit-testable.
 *
 * @param index        position of this segment within a scan
 * @param channel      where the text came from
 * @param channelLabel human-readable channel detail, e.g. {@code "@title"}, {@code "<meta description>"}
 * @param locator      pointer to the source node (CSS-path-like), or {@code null}
 * @param text         the raw text of the segment
 * @param style        resolved style for {@link Channel#RENDERED_TEXT}, else {@code null}
 */
public record Segment(
        int index,
        Channel channel,
        String channelLabel,
        String locator,
        String text,
        StyleSnapshot style
) {
    public static Segment renderedText(int index, String locator, String text, StyleSnapshot style) {
        return new Segment(index, Channel.RENDERED_TEXT, Channel.RENDERED_TEXT.label(), locator, text, style);
    }

    /** Convenience for the plain-text scan path. */
    public static Segment plainText(String text) {
        return new Segment(0, Channel.RENDERED_TEXT, Channel.RENDERED_TEXT.label(), null, text, null);
    }
}
