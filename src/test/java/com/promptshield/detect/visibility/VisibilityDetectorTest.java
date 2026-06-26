package com.promptshield.detect.visibility;

import com.promptshield.detect.DetectorResult;
import com.promptshield.detect.Segment;
import com.promptshield.detect.css.StyleSnapshot;
import com.promptshield.domain.DetectorCategory;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class VisibilityDetectorTest {

    private final VisibilityDetector detector = new VisibilityDetector();

    private List<String> reasons(StyleSnapshot s) {
        return detector.analyse(s);
    }

    @Test
    void plainVisibleTextHasNoReasons() {
        StyleSnapshot s = StyleSnapshot.builder()
                .fontSizePx(16.0).color("rgb(0,0,0)").backgroundColor("rgb(255,255,255)")
                .opacity(1.0).visibility("visible").display("block").build();
        assertThat(reasons(s)).isEmpty();
    }

    @Test
    void displayNone() {
        assertThat(reasons(StyleSnapshot.builder().display("none").build())).contains("display: none");
    }

    @Test
    void hiddenAttribute() {
        assertThat(reasons(StyleSnapshot.builder().hiddenAttr(true).build())).contains("hidden attribute");
    }

    @Test
    void visibilityHiddenAndCollapse() {
        assertThat(reasons(StyleSnapshot.builder().visibility("hidden").build())).contains("visibility: hidden");
        assertThat(reasons(StyleSnapshot.builder().visibility("collapse").build())).contains("visibility: collapse");
    }

    @Test
    void opacityZero() {
        assertThat(reasons(StyleSnapshot.builder().opacity(0.0).build())).contains("opacity: 0");
    }

    @Test
    void tinyFonts() {
        assertThat(reasons(StyleSnapshot.builder().fontSizePx(0.0).build())).anyMatch(r -> r.startsWith("tiny font"));
        assertThat(reasons(StyleSnapshot.builder().fontSizePx(1.0).build())).anyMatch(r -> r.startsWith("tiny font"));
        assertThat(reasons(StyleSnapshot.builder().fontSizePx(16.0).build())).noneMatch(r -> r.startsWith("tiny font"));
    }

    @Test
    void lowContrastWhiteOnWhite() {
        StyleSnapshot s = StyleSnapshot.builder()
                .color("rgb(255,255,255)").backgroundColor("rgb(255,255,255)").build();
        assertThat(reasons(s)).anyMatch(r -> r.startsWith("low contrast"));
    }

    @Test
    void transparentBackgroundNotUsedForContrast() {
        StyleSnapshot s = StyleSnapshot.builder()
                .color("rgb(255,255,255)").backgroundColor("rgba(0,0,0,0)").build();
        assertThat(reasons(s)).noneMatch(r -> r.startsWith("low contrast"));
    }

    @Test
    void textIndentOffScreen() {
        assertThat(reasons(StyleSnapshot.builder().textIndentPx(-9999.0).build()))
                .anyMatch(r -> r.startsWith("text-indent"));
    }

    @Test
    void absoluteOffScreenButNotStatic() {
        assertThat(reasons(StyleSnapshot.builder().position("absolute").leftPx(-9999.0).build()))
                .anyMatch(r -> r.startsWith("positioned off-screen"));
        assertThat(reasons(StyleSnapshot.builder().position("static").leftPx(-9999.0).build()))
                .noneMatch(r -> r.startsWith("positioned off-screen"));
    }

    @Test
    void clipAndClipPathCollapse() {
        assertThat(reasons(StyleSnapshot.builder().clip("rect(0px, 0px, 0px, 0px)").build()))
                .contains("clipped to nothing");
        assertThat(reasons(StyleSnapshot.builder().clipPath("inset(100%)").build()))
                .contains("clipped to nothing");
        assertThat(reasons(StyleSnapshot.builder().clipPath("circle(0)").build()))
                .contains("clipped to nothing");
    }

    @Test
    void zeroSizeOverflowHidden() {
        assertThat(reasons(StyleSnapshot.builder().overflow("hidden").widthPx(0.0).heightPx(0.0).build()))
                .contains("zero-size box with overflow hidden");
    }

    @Test
    void ariaHidden() {
        assertThat(reasons(StyleSnapshot.builder().ariaHidden(true).build())).contains("aria-hidden=\"true\"");
    }

    @Test
    void renderedOutsideViewport() {
        StyleSnapshot s = StyleSnapshot.builder()
                .position("absolute").leftPx(-500.0).topPx(0.0).widthPx(100.0).heightPx(20.0)
                .viewportWidthPx(1000.0).viewportHeightPx(800.0).build();
        assertThat(reasons(s)).contains("rendered outside the viewport");
    }

    @Test
    void inspectIsHidingCategoryAndSkipsNullStyle() {
        DetectorResult result = detector.inspect(
                Segment.renderedText(0, "div", "x", StyleSnapshot.builder().display("none").build())).orElseThrow();
        assertThat(result.category()).isEqualTo(DetectorCategory.HIDING);

        Optional<DetectorResult> none = detector.inspect(Segment.plainText("no style here"));
        assertThat(none).isEmpty();
    }
}
