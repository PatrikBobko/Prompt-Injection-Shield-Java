package com.promptshield.domain;

/**
 * Where a piece of analysed text came from. Everything other than
 * {@link #RENDERED_TEXT} is a "hidden channel": content that a human reading the
 * page does not normally see but that an LLM ingesting the raw HTML would.
 */
public enum Channel {
    RENDERED_TEXT("rendered text"),
    HTML_COMMENT("HTML comment"),
    ATTRIBUTE("attribute"),
    META("meta tag"),
    HIDDEN_INPUT("hidden input");

    private final String label;

    Channel(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    /** True for channels that are not rendered as page body text. */
    public boolean isHidden() {
        return this != RENDERED_TEXT;
    }
}
