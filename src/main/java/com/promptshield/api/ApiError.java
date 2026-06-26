package com.promptshield.api;

import java.util.List;

/**
 * Uniform error body for failed requests.
 *
 * @param status  HTTP status code
 * @param error   short error label
 * @param details specific messages (e.g. per-field validation errors)
 */
public record ApiError(int status, String error, List<String> details) {
}
