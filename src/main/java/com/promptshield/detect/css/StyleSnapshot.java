package com.promptshield.detect.css;

/**
 * A flat snapshot of the style/geometry values the visibility detector cares
 * about, mirroring the extension's {@code StyleSnapshot}. Object types are used
 * so that {@code null} can mean "unknown / auto / not resolvable".
 *
 * <p>Unlike the browser extension, which fills this from {@code getComputedStyle}
 * and {@code getBoundingClientRect}, the jsoup-based resolver can only populate
 * style fields it can read statically (inline styles, presentational attributes
 * and simple stylesheet rules). The geometry fields ({@code widthPx},
 * {@code heightPx}, viewport) are therefore usually {@code null} on this port;
 * the dependent checks are kept so the logic stays faithful and unit-testable
 * with synthetic snapshots.
 */
public record StyleSnapshot(
        Double fontSizePx,
        String color,
        String backgroundColor,
        Double opacity,
        String visibility,
        String display,
        Double textIndentPx,
        String position,
        Double leftPx,
        Double topPx,
        String clip,
        String clipPath,
        String overflow,
        Double widthPx,
        Double heightPx,
        Double viewportWidthPx,
        Double viewportHeightPx,
        boolean ariaHidden,
        boolean hiddenAttr
) {
    public static Builder builder() {
        return new Builder();
    }

    /** Mutable builder; keeps construction (and tests) readable given the field count. */
    public static final class Builder {
        private Double fontSizePx;
        private String color;
        private String backgroundColor;
        private Double opacity;
        private String visibility;
        private String display;
        private Double textIndentPx;
        private String position;
        private Double leftPx;
        private Double topPx;
        private String clip;
        private String clipPath;
        private String overflow;
        private Double widthPx;
        private Double heightPx;
        private Double viewportWidthPx;
        private Double viewportHeightPx;
        private boolean ariaHidden;
        private boolean hiddenAttr;

        public Builder fontSizePx(Double v) { this.fontSizePx = v; return this; }
        public Builder color(String v) { this.color = v; return this; }
        public Builder backgroundColor(String v) { this.backgroundColor = v; return this; }
        public Builder opacity(Double v) { this.opacity = v; return this; }
        public Builder visibility(String v) { this.visibility = v; return this; }
        public Builder display(String v) { this.display = v; return this; }
        public Builder textIndentPx(Double v) { this.textIndentPx = v; return this; }
        public Builder position(String v) { this.position = v; return this; }
        public Builder leftPx(Double v) { this.leftPx = v; return this; }
        public Builder topPx(Double v) { this.topPx = v; return this; }
        public Builder clip(String v) { this.clip = v; return this; }
        public Builder clipPath(String v) { this.clipPath = v; return this; }
        public Builder overflow(String v) { this.overflow = v; return this; }
        public Builder widthPx(Double v) { this.widthPx = v; return this; }
        public Builder heightPx(Double v) { this.heightPx = v; return this; }
        public Builder viewportWidthPx(Double v) { this.viewportWidthPx = v; return this; }
        public Builder viewportHeightPx(Double v) { this.viewportHeightPx = v; return this; }
        public Builder ariaHidden(boolean v) { this.ariaHidden = v; return this; }
        public Builder hiddenAttr(boolean v) { this.hiddenAttr = v; return this; }

        public StyleSnapshot build() {
            return new StyleSnapshot(
                    fontSizePx, color, backgroundColor, opacity, visibility, display,
                    textIndentPx, position, leftPx, topPx, clip, clipPath, overflow,
                    widthPx, heightPx, viewportWidthPx, viewportHeightPx,
                    ariaHidden, hiddenAttr);
        }
    }
}
