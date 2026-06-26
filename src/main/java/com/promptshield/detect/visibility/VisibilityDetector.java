package com.promptshield.detect.visibility;

import com.promptshield.detect.Detector;
import com.promptshield.detect.DetectorResult;
import com.promptshield.detect.Segment;
import com.promptshield.detect.css.Contrast;
import com.promptshield.detect.css.CssColor;
import com.promptshield.detect.css.Rgba;
import com.promptshield.detect.css.StyleSnapshot;
import com.promptshield.domain.DetectorCategory;
import com.promptshield.domain.Evidence;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Decides whether a segment's source element is effectively invisible to a
 * human. Ported from {@code visibility.js}. This is a {@link DetectorCategory#HIDING}
 * detector: on its own it never produces a finding; it only raises the severity
 * of co-located injection or steganography.
 *
 * <p>The browser fed this from {@code getComputedStyle}/{@code getBoundingClientRect}.
 * The jsoup port can only supply statically resolvable style (inline styles,
 * presentational attributes, simple stylesheet rules), so geometry-dependent
 * checks (off-viewport, zero-size overflow) rarely fire here even though the
 * logic is preserved and unit-tested with synthetic snapshots.
 */
@Component
public class VisibilityDetector implements Detector {

    public static final String ID = "visibility";

    /** Tunable thresholds, kept together as in the original. */
    static final double TINY_FONT_PX = 1.0;
    static final double MIN_CONTRAST = 1.5;
    static final double OFFSCREEN_PX = 999.0;

    @Override
    public String id() {
        return ID;
    }

    @Override
    public DetectorCategory category() {
        return DetectorCategory.HIDING;
    }

    @Override
    public Optional<DetectorResult> inspect(Segment segment) {
        StyleSnapshot style = segment.style();
        if (style == null) {
            return Optional.empty();
        }
        List<String> reasons = analyse(style);
        if (reasons.isEmpty()) {
            return Optional.empty();
        }
        List<Evidence> evidence = reasons.stream()
                .map(r -> Evidence.note("hidden-style", r))
                .toList();
        return Optional.of(new DetectorResult(ID, DetectorCategory.HIDING, reasons, evidence));
    }

    /** The reasons an element is hidden; empty means visible. */
    List<String> analyse(StyleSnapshot s) {
        List<String> reasons = new ArrayList<>();

        if ("none".equals(s.display())) {
            reasons.add("display: none");
        }
        // The HTML hidden attribute is the static-markup equivalent of display:none;
        // not in the original (which only saw computed styles) but a real hiding vector.
        if (s.hiddenAttr()) {
            reasons.add("hidden attribute");
        }
        if ("hidden".equals(s.visibility()) || "collapse".equals(s.visibility())) {
            reasons.add("visibility: " + s.visibility());
        }
        if (s.opacity() != null && s.opacity() == 0.0) {
            reasons.add("opacity: 0");
        }
        if (s.fontSizePx() != null && s.fontSizePx() <= TINY_FONT_PX) {
            reasons.add("tiny font-size (" + px(s.fontSizePx()) + "px)");
        }

        // Same-ish text/background colour. Only meaningful when both are opaque:
        // a transparent background tells us nothing about the colour painted behind it.
        Rgba fg = CssColor.parse(s.color());
        Rgba bg = CssColor.parse(s.backgroundColor());
        if (fg != null && bg != null && fg.a() > 0 && bg.a() > 0) {
            double ratio = Contrast.ratio(fg, bg);
            if (ratio < MIN_CONTRAST) {
                reasons.add("low contrast (ratio " + String.format(Locale.ROOT, "%.2f", ratio) + ")");
            }
        }

        if (s.textIndentPx() != null && s.textIndentPx() <= -OFFSCREEN_PX) {
            reasons.add("text-indent off-screen (" + px(s.textIndentPx()) + "px)");
        }

        if ("absolute".equals(s.position()) || "fixed".equals(s.position())) {
            if (s.leftPx() != null && s.leftPx() <= -OFFSCREEN_PX) {
                reasons.add("positioned off-screen (left " + px(s.leftPx()) + "px)");
            }
            if (s.topPx() != null && s.topPx() <= -OFFSCREEN_PX) {
                reasons.add("positioned off-screen (top " + px(s.topPx()) + "px)");
            }
            if (isRectOffViewport(s)) {
                reasons.add("rendered outside the viewport");
            }
        }

        if (isCollapsedClip(s.clip()) || isCollapsedClipPath(s.clipPath())) {
            reasons.add("clipped to nothing");
        }

        if ("hidden".equals(s.overflow())
                && ((s.widthPx() != null && s.widthPx() == 0.0) || (s.heightPx() != null && s.heightPx() == 0.0))) {
            reasons.add("zero-size box with overflow hidden");
        }

        if (s.ariaHidden()) {
            reasons.add("aria-hidden=\"true\"");
        }

        return reasons;
    }

    /** True if the element's box is entirely outside the viewport. */
    private static boolean isRectOffViewport(StyleSnapshot s) {
        if (s.leftPx() == null || s.topPx() == null || s.widthPx() == null || s.heightPx() == null) {
            return false;
        }
        double left = s.leftPx();
        double top = s.topPx();
        double right = left + s.widthPx();
        double bottom = top + s.heightPx();
        double vw = s.viewportWidthPx() != null ? s.viewportWidthPx() : Double.POSITIVE_INFINITY;
        double vh = s.viewportHeightPx() != null ? s.viewportHeightPx() : Double.POSITIVE_INFINITY;
        return right <= 0 || bottom <= 0 || left >= vw || top >= vh;
    }

    /** clip: rect(0,0,0,0) (the classic visually-hidden pattern). */
    static boolean isCollapsedClip(String clip) {
        if (clip == null || clip.isBlank() || "auto".equals(clip)) {
            return false;
        }
        String trimmed = clip.trim();
        if (!trimmed.startsWith("rect(") || !trimmed.endsWith(")")) {
            return false;
        }
        String inner = trimmed.substring(5, trimmed.length() - 1);
        String[] parts = inner.split("[,\\s]+");
        double[] nums = new double[4];
        int n = 0;
        for (String p : parts) {
            if (p.isEmpty()) {
                continue;
            }
            if (n >= 4) {
                return false;
            }
            try {
                nums[n++] = Double.parseDouble(p.replaceAll("px$", ""));
            } catch (NumberFormatException e) {
                return false;
            }
        }
        // rect(top right bottom left): collapses when right<=left and bottom<=top.
        if (n == 4) {
            double t = nums[0], r = nums[1], b = nums[2], l = nums[3];
            return r - l <= 0 || b - t <= 0;
        }
        return false;
    }

    /** clip-path that collapses the box, e.g. inset(100%), circle(0). */
    static boolean isCollapsedClipPath(String clipPath) {
        if (clipPath == null || clipPath.isBlank() || "none".equals(clipPath)) {
            return false;
        }
        String cp = clipPath.toLowerCase(Locale.ROOT);
        if (cp.matches(".*inset\\(\\s*(100%|50%\\s+50%\\s+50%\\s+50%).*")) {
            return true;
        }
        return cp.matches(".*circle\\(\\s*0(px|%)?\\s*[)\\s].*");
    }

    /** Format a px value without a trailing ".0" for whole numbers. */
    private static String px(double v) {
        if (v == Math.rint(v) && !Double.isInfinite(v)) {
            return Long.toString((long) v);
        }
        return Double.toString(v);
    }
}
