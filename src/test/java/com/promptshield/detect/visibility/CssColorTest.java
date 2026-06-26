package com.promptshield.detect.visibility;

import com.promptshield.detect.css.Contrast;
import com.promptshield.detect.css.CssColor;
import com.promptshield.detect.css.Rgba;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

class CssColorTest {

    @Test
    void parsesRgb() {
        assertThat(CssColor.parse("rgb(255, 0, 0)")).isEqualTo(new Rgba(255, 0, 0, 1));
    }

    @Test
    void parsesRgbaAlpha() {
        assertThat(CssColor.parse("rgba(0,0,0,0)").a()).isZero();
    }

    @Test
    void parsesRgbPercentageChannelsLikeParseFloat() {
        // "50%" -> 50, matching the original's tolerant parseFloat behaviour.
        assertThat(CssColor.parse("rgb(50%, 0, 0)").r()).isEqualTo(50);
    }

    @Test
    void parsesShortHex() {
        assertThat(CssColor.parse("#fff")).isEqualTo(new Rgba(255, 255, 255, 1));
    }

    @Test
    void parsesLongHex() {
        assertThat(CssColor.parse("#112233").g()).isEqualTo(0x22);
    }

    @Test
    void parsesHexWithAlpha() {
        assertThat(CssColor.parse("#11223344").a()).isCloseTo(0x44 / 255.0, within(1e-9));
    }

    @Test
    void parsesNamedColours() {
        assertThat(CssColor.parse("black")).isEqualTo(new Rgba(0, 0, 0, 1));
        assertThat(CssColor.parse("transparent").a()).isZero();
    }

    @Test
    void rejectsGarbage() {
        assertThat(CssColor.parse("not-a-color")).isNull();
        assertThat(CssColor.parse(null)).isNull();
        assertThat(CssColor.parse("")).isNull();
    }

    @Test
    void contrastBlackOnWhiteIsAbout21() {
        double ratio = Contrast.ratio(CssColor.parse("black"), CssColor.parse("white"));
        assertThat(ratio).isCloseTo(21.0, within(0.1));
    }

    @Test
    void contrastSameColourIsOne() {
        Rgba black = CssColor.parse("black");
        assertThat(Contrast.ratio(black, black)).isEqualTo(1.0);
    }
}
