package com.anthropic.audit.model;

import java.time.Instant;
import java.util.Map;

/**
 * An immutable, append-only audit event.
 *
 * <p>{@code sequence}, {@code timestamp}, {@code recordHash} and {@code previousHash} are
 * assigned by the store at ingestion time, never by the caller — this is what makes the
 * hash chain trustworthy as a tamper-evidence mechanism.
 */
public record EventRecord(
        long sequence,
        String eventType,
        String actorId,
        String resourceType,
        String resourceId,
        Map<String, Object> payload,
        Instant timestamp,
        String previousHash,
        String recordHash
) {
}
