package com.promptshield.extract;

import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Builds a reasonably-unique CSS selector path for an element, e.g.
 * {@code div#main > ul > li:nth-of-type(3) > span}. Java/jsoup port of
 * {@code cssPath.js}.
 */
public final class CssPath {

    private CssPath() {
    }

    public static String of(Element el) {
        if (el == null) {
            return "";
        }
        Deque<String> parts = new ArrayDeque<>();
        Element node = el;
        while (node != null) {
            String tag = node.tagName().toLowerCase();
            if (!node.id().isEmpty()) {
                parts.addFirst(tag + "#" + escape(node.id()));
                break;
            }

            String selector = tag;
            Element parent = node.parent() instanceof Element e ? e : null;
            if (parent != null) {
                int index = sameTagIndex(parent, node);
                int sameTagCount = countSameTag(parent, node);
                if (sameTagCount > 1) {
                    selector += ":nth-of-type(" + index + ")";
                }
            }
            parts.addFirst(selector);

            if (tag.equals("html") || parent == null) {
                break;
            }
            node = parent;
        }
        return String.join(" > ", parts);
    }

    private static int countSameTag(Element parent, Element node) {
        int count = 0;
        for (Element child : parent.children()) {
            if (child.tagName().equals(node.tagName())) {
                count++;
            }
        }
        return count;
    }

    /** 1-based index of {@code node} among same-tag siblings. */
    private static int sameTagIndex(Element parent, Element node) {
        int index = 0;
        Elements children = parent.children();
        for (Element child : children) {
            if (child.tagName().equals(node.tagName())) {
                index++;
                if (child == node) {
                    return index;
                }
            }
        }
        return index;
    }

    private static String escape(String s) {
        return s.replaceAll("([^a-zA-Z0-9_-])", "\\\\$1");
    }
}
