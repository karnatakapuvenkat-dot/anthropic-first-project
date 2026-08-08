package com.anthropic.audit.model;

/**
 * One field of an event's payload, carrying both its current value and a permanent
 * commitment to the value that existed at ingestion time.
 *
 * <p>{@code contentHash} is {@code SHA256(canonicalJson(originalValue))}, computed once
 * when the record is created and never changed afterward. The record-level hash chain is
 * built from these per-field commitments rather than from the raw payload JSON. This is
 * what makes redaction possible without breaking the chain: {@link #redact()} clears
 * {@code value} but keeps {@code contentHash} untouched, so the payload commitment — and
 * therefore {@code recordHash} — recomputes identically before and after redaction.
 *
 * <p>{@code contentHash} alone does not leak the original value (it is a one-way digest),
 * but for fields with small or guessable value spaces it can still be brute-forced by
 * hashing candidate values and comparing. Callers redacting such fields should be aware
 * the hash itself is not a strong secrecy guarantee — see the redaction design notes in
 * {@code EventStore}.
 */
public record PayloadField(
        Object value,
        String contentHash,
        boolean redacted,
        java.time.Instant redactedAt,
        String redactionReason
) {
    public static PayloadField of(Object value, String contentHash) {
        return new PayloadField(value, contentHash, false, null, null);
    }

    public PayloadField redact(java.time.Instant when, String reason) {
        return new PayloadField(null, contentHash, true, when, reason);
    }
}
