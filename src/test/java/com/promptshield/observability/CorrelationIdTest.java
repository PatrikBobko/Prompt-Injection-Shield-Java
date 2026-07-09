package com.promptshield.observability;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CorrelationIdTest {

    @Test
    void retainsSafeCallerSuppliedValue() {
        String supplied = "gateway.7e3f-42_request";

        assertEquals(supplied, CorrelationId.resolve(supplied));
        assertTrue(CorrelationId.isValid(supplied));
    }

    @Test
    void replacesPotentialLogForgingValue() {
        String resolved = CorrelationId.resolve("valid-id\r\nforged-log-line");

        assertFalse(CorrelationId.isValid("valid-id\r\nforged-log-line"));
        UUID.fromString(resolved);
    }
}
