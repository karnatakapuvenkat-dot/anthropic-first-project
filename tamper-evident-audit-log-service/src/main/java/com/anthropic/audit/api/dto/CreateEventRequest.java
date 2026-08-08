package com.anthropic.audit.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.Map;

/**
 * Inbound event submission. Deliberately has no timestamp field: timestamps are
 * server-assigned at ingestion time (see EventStore) so that callers cannot forge
 * or backdate audit history.
 */
public record CreateEventRequest(
        @NotBlank String eventType,
        @NotBlank String actorId,
        @NotBlank String resourceType,
        @NotBlank String resourceId,
        @NotNull Map<String, Object> payload
) {
}
