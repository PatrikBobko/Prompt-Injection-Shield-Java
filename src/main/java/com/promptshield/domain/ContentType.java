package com.promptshield.domain;

/**
 * How the submitted content should be interpreted.
 */
public enum ContentType {
    /** Parse with jsoup; walk text nodes, comments, attributes, meta and hidden inputs. */
    HTML,
    /** Treat the payload as a single plain-text blob (no DOM extraction). */
    TEXT
}
