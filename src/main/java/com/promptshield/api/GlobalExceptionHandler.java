package com.promptshield.api;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;

/**
 * Translates the common request failures into a consistent {@link ApiError} body.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    /** Bean-validation failures (e.g. blank or oversized content). */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException ex) {
        List<String> details = ex.getBindingResult().getFieldErrors().stream()
                .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
                .toList();
        return badRequest("validation failed", details);
    }

    /** Malformed or unreadable JSON body (e.g. an unknown contentType enum value). */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiError> handleUnreadable(HttpMessageNotReadableException ex) {
        return badRequest("malformed request body", List.of("the request body could not be parsed"));
    }

    private static ResponseEntity<ApiError> badRequest(String error, List<String> details) {
        return ResponseEntity.badRequest().body(
                new ApiError(HttpStatus.BAD_REQUEST.value(), error, details));
    }
}
