package com.promptshield.detect.css;

import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CSS colour parsing, ported from {@code color.js}. Handles the forms inline
 * styles actually use: {@code rgb()}/{@code rgba()}, {@code #rgb}/{@code #rgba}/
 * {@code #rrggbb}/{@code #rrggbbaa}, and a small set of named colours. Returns
 * {@code null} for anything it cannot parse.
 */
public final class CssColor {

    /** Leading numeric token, mirroring JS {@code parseFloat} (e.g. "50%" -> 50). */
    private static final Pattern LEADING_NUMBER =
            Pattern.compile("^[+-]?(?:\\d+\\.?\\d*|\\.\\d+)(?:[eE][+-]?\\d+)?");

    private static final Map<String, Rgba> NAMED = Map.of(
            "black", new Rgba(0, 0, 0, 1),
            "white", new Rgba(255, 255, 255, 1),
            "red", new Rgba(255, 0, 0, 1),
            "green", new Rgba(0, 128, 0, 1),
            "blue", new Rgba(0, 0, 255, 1),
            "transparent", new Rgba(0, 0, 0, 0));

    private CssColor() {
    }

    public static Rgba parse(String input) {
        if (input == null) {
            return null;
        }
        String str = input.trim().toLowerCase(Locale.ROOT);
        if (str.isEmpty()) {
            return null;
        }
        if (NAMED.containsKey(str)) {
            return NAMED.get(str);
        }
        if (str.charAt(0) == '#') {
            return parseHex(str.substring(1));
        }
        if (str.startsWith("rgb")) {
            return parseRgbFunction(str);
        }
        return null;
    }

    private static Rgba parseHex(String hex) {
        try {
            return switch (hex.length()) {
                case 3, 4 -> {
                    int r = Integer.parseInt(dup(hex.charAt(0)), 16);
                    int g = Integer.parseInt(dup(hex.charAt(1)), 16);
                    int b = Integer.parseInt(dup(hex.charAt(2)), 16);
                    double a = hex.length() == 4 ? Integer.parseInt(dup(hex.charAt(3)), 16) / 255.0 : 1.0;
                    yield new Rgba(r, g, b, a);
                }
                case 6, 8 -> {
                    int r = Integer.parseInt(hex.substring(0, 2), 16);
                    int g = Integer.parseInt(hex.substring(2, 4), 16);
                    int b = Integer.parseInt(hex.substring(4, 6), 16);
                    double a = hex.length() == 8 ? Integer.parseInt(hex.substring(6, 8), 16) / 255.0 : 1.0;
                    yield new Rgba(r, g, b, a);
                }
                default -> null;
            };
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static Rgba parseRgbFunction(String str) {
        int open = str.indexOf('(');
        int close = str.indexOf(')');
        if (open < 0 || close < 0 || close < open) {
            return null;
        }
        String inner = str.substring(open + 1, close);
        String[] parts = inner.split("[,\\s/]+");
        // Filter empties (leading separators etc.).
        int n = 0;
        String[] cleaned = new String[parts.length];
        for (String p : parts) {
            if (!p.isEmpty()) {
                cleaned[n++] = p;
            }
        }
        if (n < 3) {
            return null;
        }
        try {
            int r = clamp255(jsParseFloat(cleaned[0]));
            int g = clamp255(jsParseFloat(cleaned[1]));
            int b = clamp255(jsParseFloat(cleaned[2]));
            double a = n >= 4 ? jsParseFloat(cleaned[3]) : 1.0;
            return new Rgba(r, g, b, a);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** Reads the leading numeric token, like JS parseFloat; throws if none. */
    private static double jsParseFloat(String s) {
        Matcher m = LEADING_NUMBER.matcher(s);
        if (m.find()) {
            return Double.parseDouble(m.group());
        }
        throw new NumberFormatException(s);
    }

    private static String dup(char c) {
        return new String(new char[] {c, c});
    }

    private static int clamp255(double n) {
        return (int) Math.max(0, Math.min(255, Math.round(n)));
    }
}
