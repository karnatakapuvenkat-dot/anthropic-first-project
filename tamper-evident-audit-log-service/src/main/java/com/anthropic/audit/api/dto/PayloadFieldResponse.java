package com.anthropic.audit.api.dto;

import com.anthropic.audit.model.PayloadField;

import java.time.Instant;

public record PayloadFieldResponse(
        Object value,
        String contentHash,
        boolean redacted,
        Instant redactedAt,
        String redactionReason
) {
    public static PayloadFieldResponse from(PayloadField field) {
        return new PayloadFieldResponse(
                field.value(),
                field.contentHash(),
                field.redacted(),
                field.redactedAt(),
                field.redactionReason()
        );
    }
}
