package com.anthropic.audit.api.dto;

public record VerifyChainResponse(
        boolean intact,
        Long firstBrokenSequence
) {
    public static VerifyChainResponse ok() {
        return new VerifyChainResponse(true, null);
    }

    public static VerifyChainResponse brokenAt(long sequence) {
        return new VerifyChainResponse(false, sequence);
    }
}
