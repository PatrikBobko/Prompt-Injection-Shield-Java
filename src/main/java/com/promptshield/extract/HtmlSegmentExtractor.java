package com.promptshield.extract;

import com.promptshield.detect.Segment;
import com.promptshield.detect.css.StyleSnapshot;
import com.promptshield.domain.Channel;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Attribute;
import org.jsoup.nodes.Comment;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Node;
import org.jsoup.nodes.TextNode;
import org.jsoup.select.NodeTraversor;
import org.jsoup.select.NodeVisitor;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Turns HTML into the flat {@link Segment} list the detectors consume. This is
 * the only DOM-aware code in the pipeline; it mirrors the extension's
 * {@code scanner.js} (rendered text nodes) and {@code extract.js} (hidden
 * channels: comments, attributes, meta, hidden inputs).
 */
@Component
public class HtmlSegmentExtractor {

    /** Ignore short, almost-certainly-benign channel strings (mirrors extract.js). */
    static final int MIN_CHANNEL_TEXT_LENGTH = 24;

    private static final Set<String> SKIP_TAGS = Set.of("script", "style", "noscript", "template");
    private static final List<String> TEXT_ATTRS = List.of("title", "alt", "aria-label", "placeholder");

    public List<Segment> extract(String html) {
        Document doc = Jsoup.parse(html == null ? "" : html);
        ComputedStyleResolver resolver = new ComputedStyleResolver(doc);
        List<Segment> segments = new ArrayList<>();
        int[] index = {0};

        collectRenderedText(doc, resolver, segments, index);
        collectComments(doc, segments, index);
        collectAttributes(doc, segments, index);
        collectMeta(doc, segments, index);
        collectHiddenInputs(doc, segments, index);

        return segments;
    }

    private void collectRenderedText(Document doc, ComputedStyleResolver resolver,
                                     List<Segment> segments, int[] index) {
        // Walk only the body (as the browser walked document.body), so head-only
        // content like <title> isn't treated as rendered page text.
        Node root = doc.body() != null ? doc.body() : doc;
        NodeTraversor.traverse(new NodeVisitor() {
            @Override
            public void head(Node node, int depth) {
                if (!(node instanceof TextNode tn)) {
                    return;
                }
                if (!(tn.parent() instanceof Element parent) || isInSkippedSubtree(parent)) {
                    return;
                }
                String text = tn.getWholeText();
                if (text == null || text.strip().isEmpty()) {
                    return;
                }
                StyleSnapshot style = resolver.snapshot(parent);
                segments.add(Segment.renderedText(index[0]++, CssPath.of(parent), text, style));
            }

            @Override
            public void tail(Node node, int depth) {
            }
        }, root);
    }

    private void collectComments(Document doc, List<Segment> segments, int[] index) {
        NodeTraversor.traverse(new NodeVisitor() {
            @Override
            public void head(Node node, int depth) {
                if (!(node instanceof Comment comment)) {
                    return;
                }
                String text = comment.getData().strip();
                if (text.length() < MIN_CHANNEL_TEXT_LENGTH) {
                    return;
                }
                String locator = comment.parent() instanceof Element parent ? CssPath.of(parent) : null;
                segments.add(new Segment(index[0]++, Channel.HTML_COMMENT, "HTML comment", locator, text, null));
            }

            @Override
            public void tail(Node node, int depth) {
            }
        }, doc);
    }

    private void collectAttributes(Document doc, List<Segment> segments, int[] index) {
        for (Element el : doc.getAllElements()) {
            for (String name : TEXT_ATTRS) {
                if (el.hasAttr(name)) {
                    addAttributeSegment(el, name, el.attr(name), segments, index);
                }
            }
            for (Attribute attr : el.attributes()) {
                if (attr.getKey().startsWith("data-")) {
                    addAttributeSegment(el, attr.getKey(), attr.getValue(), segments, index);
                }
            }
        }
    }

    private void addAttributeSegment(Element el, String name, String value,
                                     List<Segment> segments, int[] index) {
        String v = value == null ? "" : value.strip();
        if (v.length() >= MIN_CHANNEL_TEXT_LENGTH) {
            segments.add(new Segment(index[0]++, Channel.ATTRIBUTE, "@" + name, CssPath.of(el), v, null));
        }
    }

    private void collectMeta(Document doc, List<Segment> segments, int[] index) {
        for (Element meta : doc.select("meta[content]")) {
            String v = meta.attr("content").strip();
            if (v.length() < MIN_CHANNEL_TEXT_LENGTH) {
                continue;
            }
            String key = firstNonEmpty(meta.attr("name"), meta.attr("property"), "meta");
            segments.add(new Segment(index[0]++, Channel.META, "<meta " + key + ">", CssPath.of(meta), v, null));
        }
    }

    private void collectHiddenInputs(Document doc, List<Segment> segments, int[] index) {
        for (Element input : doc.select("input[type=hidden]")) {
            String v = input.attr("value").strip();
            if (v.length() >= MIN_CHANNEL_TEXT_LENGTH) {
                segments.add(new Segment(index[0]++, Channel.HIDDEN_INPUT, "hidden <input>", CssPath.of(input), v, null));
            }
        }
    }

    private static boolean isInSkippedSubtree(Element el) {
        for (Element e = el; e != null; e = e.parent() instanceof Element p ? p : null) {
            if (SKIP_TAGS.contains(e.tagName().toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private static String firstNonEmpty(String... values) {
        for (String v : values) {
            if (v != null && !v.isEmpty()) {
                return v;
            }
        }
        return "";
    }
}
