package com.promptshield.extract;

import com.promptshield.detect.css.CssColor;
import com.promptshield.detect.css.Rgba;
import com.promptshield.detect.css.StyleSnapshot;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Resolves a {@link StyleSnapshot} for an element from statically available
 * information: inline {@code style} attributes, presentational attributes
 * ({@code hidden}, {@code aria-hidden}) and simple {@code <style>}-block rules
 * matched via jsoup selectors.
 *
 * <p>This is the jsoup analogue of the browser's {@code getComputedStyle}, with
 * documented limitations: there is no full CSS cascade (specificity is ignored;
 * stylesheet rules apply in document order, inline styles win), no
 * {@code @media}/pseudo handling, and no layout, so geometry fields are left
 * unset. One instance is built per document; selectors are matched once up front.
 */
public class ComputedStyleResolver {

    /** A leading number with no trailing characters (after a "px" strip). */
    private static final Pattern LEADING_NUMBER = Pattern.compile("^[+-]?(?:\\d+\\.?\\d*|\\.\\d+)$");
    private static final Pattern COMMENTS = Pattern.compile("(?s)/\\*.*?\\*/");

    private final Map<Element, Map<String, String>> sheetStyles = new IdentityHashMap<>();

    public ComputedStyleResolver(Document doc) {
        for (Element styleEl : doc.select("style")) {
            applyStylesheet(doc, styleEl.data());
        }
    }

    /** Resolve the snapshot for one element. */
    public StyleSnapshot snapshot(Element el) {
        Map<String, String> d = mergedDeclarations(el);
        return StyleSnapshot.builder()
                .display(d.get("display"))
                .visibility(d.get("visibility"))
                .opacity(parseDoubleOrNull(d.get("opacity")))
                .fontSizePx(parsePx(d.get("font-size")))
                .color(d.get("color"))
                .backgroundColor(effectiveBackground(el))
                .textIndentPx(parsePx(d.get("text-indent")))
                .position(d.get("position"))
                .leftPx(parsePx(d.get("left")))
                .topPx(parsePx(d.get("top")))
                .clip(d.get("clip"))
                .clipPath(d.get("clip-path"))
                .overflow(d.get("overflow"))
                .ariaHidden(el.closest("[aria-hidden=true]") != null)
                .hiddenAttr(el.closest("[hidden]") != null)
                .build();
    }

    private void applyStylesheet(Document doc, String css) {
        String body = COMMENTS.matcher(css).replaceAll("");
        for (String block : body.split("}")) {
            int brace = block.indexOf('{');
            if (brace < 0) {
                continue;
            }
            String selectorList = block.substring(0, brace).trim();
            String declText = block.substring(brace + 1).trim();
            // Skip at-rules (@media/@keyframes/@font-face); their inner rules are
            // not applied (documented limitation).
            if (selectorList.isEmpty() || selectorList.startsWith("@")) {
                continue;
            }
            Map<String, String> decls = parseDeclarations(declText);
            if (decls.isEmpty()) {
                continue;
            }
            for (String raw : selectorList.split(",")) {
                String selector = raw.trim();
                if (selector.isEmpty() || selector.startsWith("@") || selector.contains("::") || selector.contains(":")) {
                    continue; // skip pseudo-classes/elements we can't statically resolve
                }
                try {
                    for (Element el : doc.select(selector)) {
                        sheetStyles.computeIfAbsent(el, k -> new LinkedHashMap<>()).putAll(decls);
                    }
                } catch (RuntimeException ignored) {
                    // Unsupported selector syntax: skip rather than fail the scan.
                }
            }
        }
    }

    /** Stylesheet declarations (document order) overlaid with inline styles. */
    private Map<String, String> mergedDeclarations(Element el) {
        Map<String, String> merged = new LinkedHashMap<>();
        Map<String, String> sheet = sheetStyles.get(el);
        if (sheet != null) {
            merged.putAll(sheet);
        }
        merged.putAll(parseDeclarations(el.attr("style")));
        return merged;
    }

    /** First opaque background colour walking up from {@code el}; defaults to white. */
    private String effectiveBackground(Element start) {
        Element node = start;
        while (node != null) {
            String bg = backgroundColorValue(node);
            Rgba c = CssColor.parse(bg);
            if (c != null && c.a() > 0) {
                return bg;
            }
            node = node.parent() instanceof Element e ? e : null;
        }
        return "rgb(255, 255, 255)";
    }

    private String backgroundColorValue(Element el) {
        Map<String, String> d = mergedDeclarations(el);
        String bc = d.get("background-color");
        if (bc != null) {
            return bc;
        }
        String bg = d.get("background");
        return bg != null ? colorFromShorthand(bg) : null;
    }

    /** Pull a colour out of a {@code background} shorthand value, if present. */
    private static String colorFromShorthand(String shorthand) {
        if (CssColor.parse(shorthand.trim()) != null) {
            return shorthand.trim();
        }
        for (String token : shorthand.trim().split("\\s+")) {
            if (CssColor.parse(token) != null) {
                return token;
            }
        }
        return null;
    }

    private static Map<String, String> parseDeclarations(String text) {
        Map<String, String> map = new LinkedHashMap<>();
        if (text == null || text.isBlank()) {
            return map;
        }
        for (String decl : text.split(";")) {
            int colon = decl.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            String prop = decl.substring(0, colon).trim().toLowerCase(Locale.ROOT);
            String value = decl.substring(colon + 1).trim().toLowerCase(Locale.ROOT);
            if (!prop.isEmpty() && !value.isEmpty()) {
                map.put(prop, value);
            }
        }
        return map;
    }

    private static Double parsePx(String value) {
        if (value == null) {
            return null;
        }
        String s = value.trim();
        if (s.endsWith("px")) {
            s = s.substring(0, s.length() - 2).trim();
        }
        if (LEADING_NUMBER.matcher(s).matches()) {
            try {
                return Double.parseDouble(s);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    private static Double parseDoubleOrNull(String value) {
        if (value == null) {
            return null;
        }
        try {
            return Double.parseDouble(value.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
