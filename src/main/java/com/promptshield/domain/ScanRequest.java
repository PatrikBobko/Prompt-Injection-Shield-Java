package com.promptshield.domain;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Request body for {@code POST /api/v1/scan}.
 *
 * @param content     the HTML or plain text to analyse
 * @param contentType how to interpret {@code content}; defaults to {@link ContentType#HTML}
 */
public record ScanRequest(
        @NotBlank(message = "content must not be blank")
        @Size(max = ScanRequest.MAX_CONTENT_CHARS,
                message = "content exceeds the maximum of {max} characters")
        String content,

        ContentType contentType
) {
    /** Reject pathologically large payloads before parsing. */
    public static final int MAX_CONTENT_CHARS = 2_000_000;

    public ContentType contentTypeOrDefault() {
        return contentType == null ? ContentType.HTML : contentType;
    }
}
