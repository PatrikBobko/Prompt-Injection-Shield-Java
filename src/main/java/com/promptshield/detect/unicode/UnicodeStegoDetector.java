package com.promptshield.detect.unicode;

import com.promptshield.detect.Detector;
import com.promptshield.detect.DetectorResult;
import com.promptshield.detect.Segment;
import com.promptshield.domain.DetectorCategory;
import com.promptshield.domain.Evidence;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Detects invisible / steganographic Unicode: zero-width characters, bidi
 * override controls, and the Unicode Tags block (U+E0000..U+E007F) used to
 * smuggle invisible ASCII into text. Ported from the extension's {@code unicode.js}.
 *
 * <p>Indices are tracked in UTF-16 code units (advancing by
 * {@link Character#charCount(int)}) so they line up with Java {@code String}
 * indexing, exactly as the original advanced by UTF-16 code units to stay
 * DOM-aligned.
 */
@Component
public class UnicodeStegoDetector implements Detector {

    public static final String ID = "unicode-stego";

    /** Zero-width / invisible joiners and the BOM. */
    private static final Set<Integer> ZERO_WIDTH = Set.of(
            0x200B, // ZERO WIDTH SPACE
            0x200C, // ZERO WIDTH NON-JOINER
            0x200D, // ZERO WIDTH JOINER
            0xFEFF  // ZERO WIDTH NO-BREAK SPACE / BOM
    );

    /** Bidirectional override / isolate controls. */
    private static final Set<Integer> BIDI = Set.of(
            0x202A, // LRE
            0x202B, // RLE
            0x202C, // PDF
            0x202D, // LRO
            0x202E, // RLO
            0x2066, // LRI
            0x2067, // RLI
            0x2068, // FSI
            0x2069  // PDI
    );

    private static final int TAGS_START = 0xE0000;
    private static final int TAGS_END = 0xE007F;
    private static final int TAG_LANGUAGE = 0xE0001;
    private static final int TAG_CANCEL = 0xE007F;
    private static final int TAG_PRINTABLE_LO = 0xE0020;
    private static final int TAG_PRINTABLE_HI = 0xE007E;

    @Override
    public String id() {
        return ID;
    }

    @Override
    public DetectorCategory category() {
        return DetectorCategory.STEGO;
    }

    @Override
    public Optional<DetectorResult> inspect(Segment segment) {
        String text = segment.text();
        if (text == null || text.isEmpty()) {
            return Optional.empty();
        }

        List<Integer> zeroWidth = new ArrayList<>();
        List<Integer> bidi = new ArrayList<>();
        List<Integer> tags = new ArrayList<>();
        StringBuilder decoded = new StringBuilder();
        int firstTagIndex = -1;
        int firstZeroWidthIndex = -1;
        int firstBidiIndex = -1;

        int i = 0;
        while (i < text.length()) {
            int cp = text.codePointAt(i);
            if (ZERO_WIDTH.contains(cp)) {
                if (firstZeroWidthIndex < 0) {
                    firstZeroWidthIndex = i;
                }
                zeroWidth.add(i);
            } else if (BIDI.contains(cp)) {
                if (firstBidiIndex < 0) {
                    firstBidiIndex = i;
                }
                bidi.add(i);
            } else if (cp >= TAGS_START && cp <= TAGS_END) {
                if (firstTagIndex < 0) {
                    firstTagIndex = i;
                }
                tags.add(i);
                decoded.append(decodeTag(cp));
            }
            i += Character.charCount(cp);
        }

        if (zeroWidth.isEmpty() && bidi.isEmpty() && tags.isEmpty()) {
            return Optional.empty();
        }

        List<String> reasons = new ArrayList<>();
        List<Evidence> evidence = new ArrayList<>();

        if (!zeroWidth.isEmpty()) {
            reasons.add("zero-width characters (" + zeroWidth.size() + ")");
            evidence.add(Evidence.at("zero-width", "", firstZeroWidthIndex, zeroWidth.size()));
        }
        if (!bidi.isEmpty()) {
            reasons.add("bidirectional override characters (" + bidi.size() + ")");
            evidence.add(Evidence.at("bidi", "", firstBidiIndex, bidi.size()));
        }
        if (!tags.isEmpty()) {
            String decodedPayload = decoded.toString();
            String preview = decodedPayload.isEmpty() ? "" : ": \"" + decodedPayload + "\"";
            reasons.add("Unicode Tags payload (" + tags.size() + " chars)" + preview);
            evidence.add(Evidence.at("tags-payload", "", firstTagIndex, tags.size())
                    .withDecoded(decodedPayload.isEmpty() ? null : decodedPayload));
        }

        return Optional.of(new DetectorResult(ID, DetectorCategory.STEGO, reasons, evidence));
    }

    /**
     * Decode a Tags-block code point to its ASCII equivalent, or "" for the
     * non-printable language/cancel tags. U+E0020..U+E007E map to ASCII 0x20..0x7E.
     */
    private static String decodeTag(int cp) {
        if (cp == TAG_LANGUAGE || cp == TAG_CANCEL) {
            return "";
        }
        if (cp >= TAG_PRINTABLE_LO && cp <= TAG_PRINTABLE_HI) {
            return String.valueOf((char) (cp - TAGS_START));
        }
        return "";
    }
}
