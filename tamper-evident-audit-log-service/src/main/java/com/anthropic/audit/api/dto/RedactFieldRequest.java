package com.anthropic.audit.api.dto;

import jakarta.validation.constraints.NotBlank;

public record RedactFieldRequest(
        @NotBlank String field,
        @NotBlank String reason
) {
}
