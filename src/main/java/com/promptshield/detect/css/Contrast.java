package com.promptshield.detect.css;

/**
 * WCAG 2.x luminance and contrast math, ported from {@code color.js}.
 */
public final class Contrast {

    private Contrast() {
    }

    /** Relative luminance in 0..1. */
    public static double relativeLuminance(Rgba c) {
        return 0.2126 * linearize(c.r()) + 0.7152 * linearize(c.g()) + 0.0722 * linearize(c.b());
    }

    /** Contrast ratio between two opaque colours, in [1, 21]. */
    public static double ratio(Rgba c1, Rgba c2) {
        double l1 = relativeLuminance(c1);
        double l2 = relativeLuminance(c2);
        double lighter = Math.max(l1, l2);
        double darker = Math.min(l1, l2);
        return (lighter + 0.05) / (darker + 0.05);
    }

    private static double linearize(int channel) {
        double s = channel / 255.0;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
    }
}
