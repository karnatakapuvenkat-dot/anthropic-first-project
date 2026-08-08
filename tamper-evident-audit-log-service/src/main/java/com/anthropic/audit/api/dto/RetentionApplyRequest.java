package com.anthropic.audit.api.dto;

import jakarta.validation.constraints.NotNull;

/**
 * {@code retentionWindow} uses ISO-8601 duration syntax (e.g. {@code "P90D"} for 90 days,
 * {@code "PT24H"} for 24 hours) so the retention window is caller-configurable per call
 * rather than baked into server config.
 */
public record RetentionApplyRequest(
        @NotNull java.time.Duration retentionWindow
) {
}
