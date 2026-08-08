package com.anthropic.audit.model;

import java.time.Instant;
import java.util.Map;

/**
 * An immutable, append-only audit event.
 *
 * <p>{@code sequence}, {@code timestamp}, {@code recordHash} and {@code previousHash} are
 * assigned by the store at ingestion time, never by the caller — this is what makes the
 * hash chain trustworthy as a tamper-evidence mechanism.
 *
 * <p>{@code payload} maps each field name to a {@link PayloadField}, which separates a
 * field's current value from a permanent commitment ({@code contentHash}) to its original
 * value. {@code recordHash} is computed over those per-field commitments, not over the raw
 * values — see {@link com.anthropic.audit.store.EventStore} for why this is what lets
 * fields be redacted later without invalidating the chain.
 *
 * <p>{@code archived}/{@code archivedAt} implement retention: an archived record is still
 * a full, hash-verified link in the chain — archival never alters {@code payload},
 * {@code previousHash}, or {@code recordHash}. It only marks the record as past its
 * retention window for query/lifecycle purposes. Redaction (via {@link PayloadField}) is
 * the separate mechanism that actually removes sensitive values.
 */
public record EventRecord(
        long sequence,
        String eventType,
        String actorId,
        String resourceType,
        String resourceId,
        Map<String, PayloadField> payload,
        Instant timestamp,
        String previousHash,
        String recordHash,
        boolean archived,
        Instant archivedAt
) {
}
