package com.anthropic.audit.store;

import com.anthropic.audit.api.dto.CreateEventRequest;
import com.anthropic.audit.model.EventRecord;
import com.anthropic.audit.model.PayloadField;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Append-only, hash-chained event store.
 *
 * <h2>Hash chain</h2>
 * Each record's {@code recordHash} is SHA-256 over the previous record's hash concatenated
 * with this record's own content (sequence, type, actor, resource, timestamp, and a
 * <b>payload commitment</b>). This forms a hash chain: mutating or removing any historical
 * record breaks the hash of every subsequent record, making tampering detectable.
 *
 * <p>There is intentionally no update or delete method on this class — the only mutating
 * operations are {@link #append}, {@link #redactField} and {@link #applyRetention}, and
 * none of them can alter {@code recordHash}, {@code previousHash}, or the ordering of
 * records. "Append-only" at the API level means the capability to rewrite history simply
 * does not exist in the code.
 *
 * <h2>Redaction without breaking the chain</h2>
 * The payload is not hashed as a single JSON blob. Instead, each payload field is hashed
 * independently at ingestion time into a {@link PayloadField#contentHash()}, and the
 * record's payload commitment is the hash of the sorted list of {@code field:contentHash}
 * pairs. {@code recordHash} is computed over that commitment, never over the raw values.
 *
 * <p>Redacting a field ({@link #redactField}) clears its stored value but leaves
 * {@code contentHash} untouched. Because the payload commitment depends only on field
 * names and content hashes — not values — it recomputes identically after redaction, so
 * {@code recordHash} does not change and {@link #verifyChain} does not report a break.
 * This is the same trick a Merkle tree uses to prove membership without revealing every
 * leaf: the hash is a commitment to the value, and the commitment survives the value's
 * removal.
 *
 * <p><b>Trade-offs / limitations of this design</b> (see also the class-level note in
 * {@link PayloadField}):
 * <ul>
 *   <li>Redaction is a genuine one-way operation for the store itself — once a value is
 *       cleared, the store has no way to recover it. Downstream consumers who cached the
 *       pre-redaction payload are unaffected by this class, which is out of scope here.</li>
 *   <li>{@code contentHash} is a plain SHA-256 digest with no per-field salt. For payload
 *       fields whose value space is small or guessable (e.g. a 4-digit PIN, a boolean, an
 *       enum), a party who knows {@code contentHash} can brute-force it by hashing
 *       candidates. This is acceptable for high-entropy identifiers (account numbers,
 *       SSNs, UUIDs) but callers redacting low-entropy fields should not treat
 *       {@code contentHash} as a secrecy guarantee.</li>
 *   <li>Redaction changes {@code payload}, so a naive "recompute the hash of the payload
 *       as stored" check would fail after redaction — this is precisely why verification
 *       must recompute over the field-commitment structure, not over payload values. Any
 *       future change to how payload is serialized must preserve this property.</li>
 *   <li>The set of field <i>names</i> and the record's other metadata (actor, resource,
 *       event type, timestamp) are never redactable by this mechanism — only payload
 *       values. If a field name itself is sensitive, it should not be used as a payload
 *       key.</li>
 * </ul>
 *
 * <h2>Retention / archival</h2>
 * {@link #applyRetention} marks records older than a configurable window as
 * {@link EventRecord#archived()}, on demand. Archival never touches {@code payload},
 * {@code previousHash}, or {@code recordHash} — it is a lifecycle flag only, layered on
 * top of the same immutable hash-chained records. Because of that, {@link #verifyChain}
 * requires no special case for archived records: they verify exactly like any other
 * record, so archiving a record per policy can never manifest as a false-positive break.
 * (Redaction is the separate mechanism for actually removing sensitive data; retention
 * policy typically triggers redaction of specific fields, not deletion of the record.)
 *
 * <p>Timestamps are server-assigned ({@link Instant#now()} at append time), not accepted
 * from callers, so that event history cannot be backdated or forged.
 */
@Component
public class EventStore {

    private static final String GENESIS_HASH = "0".repeat(64);

    private final List<EventRecord> records = new ArrayList<>();
    private final ReentrantLock lock = new ReentrantLock();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public EventRecord append(CreateEventRequest request) {
        lock.lock();
        try {
            long sequence = records.size();
            Instant timestamp = Instant.now();
            String previousHash = records.isEmpty()
                    ? GENESIS_HASH
                    : records.get(records.size() - 1).recordHash();

            Map<String, PayloadField> payload = buildPayloadFields(request.payload());
            String recordHash = computeHash(previousHash, sequence, request.eventType(),
                    request.actorId(), request.resourceType(), request.resourceId(),
                    timestamp, payload);

            EventRecord record = new EventRecord(
                    sequence,
                    request.eventType(),
                    request.actorId(),
                    request.resourceType(),
                    request.resourceId(),
                    payload,
                    timestamp,
                    previousHash,
                    recordHash,
                    false,
                    null
            );

            records.add(record);
            return record;
        } finally {
            lock.unlock();
        }
    }

    private Map<String, PayloadField> buildPayloadFields(Map<String, Object> rawPayload) {
        Map<String, PayloadField> fields = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : rawPayload.entrySet()) {
            fields.put(entry.getKey(), PayloadField.of(entry.getValue(), hashValue(entry.getValue())));
        }
        return fields;
    }

    public PageResult query(EventQuery query, int page, int size) {
        lock.lock();
        List<EventRecord> snapshot;
        try {
            snapshot = new ArrayList<>(records);
        } finally {
            lock.unlock();
        }

        List<EventRecord> filtered = snapshot.stream()
                .filter(r -> query.actorId() == null || query.actorId().equals(r.actorId()))
                .filter(r -> query.resourceType() == null || query.resourceType().equals(r.resourceType()))
                .filter(r -> query.resourceId() == null || query.resourceId().equals(r.resourceId()))
                .filter(r -> query.eventType() == null || query.eventType().equals(r.eventType()))
                .filter(r -> query.from() == null || !r.timestamp().isBefore(query.from()))
                .filter(r -> query.to() == null || !r.timestamp().isAfter(query.to()))
                .toList();

        long totalElements = filtered.size();
        int fromIndex = Math.min(page * size, filtered.size());
        int toIndex = Math.min(fromIndex + size, filtered.size());
        List<EventRecord> pageContent = filtered.subList(fromIndex, toIndex);

        return new PageResult(pageContent, totalElements);
    }

    /**
     * Finds a single record by sequence number, if present.
     */
    public Optional<EventRecord> findBySequence(long sequence) {
        lock.lock();
        try {
            if (sequence < 0 || sequence >= records.size()) {
                return Optional.empty();
            }
            return Optional.of(records.get((int) sequence));
        } finally {
            lock.unlock();
        }
    }

    /**
     * Redacts a single payload field on a single record. The field's value is cleared;
     * its content-hash commitment is kept, so the record's {@code recordHash} is
     * unaffected and the chain remains verifiable. See the class-level doc for the full
     * design rationale and limitations.
     *
     * @throws IllegalArgumentException if the sequence or field does not exist
     */
    public EventRecord redactField(long sequence, String fieldName, String reason) {
        lock.lock();
        try {
            if (sequence < 0 || sequence >= records.size()) {
                throw new IllegalArgumentException("No record with sequence " + sequence);
            }
            EventRecord record = records.get((int) sequence);
            PayloadField field = record.payload().get(fieldName);
            if (field == null) {
                throw new IllegalArgumentException("Record " + sequence + " has no field '" + fieldName + "'");
            }

            String recordHashBefore = record.recordHash();

            Map<String, PayloadField> updatedPayload = new LinkedHashMap<>(record.payload());
            updatedPayload.put(fieldName, field.redact(Instant.now(), reason));

            EventRecord updated = new EventRecord(
                    record.sequence(),
                    record.eventType(),
                    record.actorId(),
                    record.resourceType(),
                    record.resourceId(),
                    updatedPayload,
                    record.timestamp(),
                    record.previousHash(),
                    record.recordHash(),
                    record.archived(),
                    record.archivedAt()
            );

            String recomputed = computeHash(updated.previousHash(), updated.sequence(), updated.eventType(),
                    updated.actorId(), updated.resourceType(), updated.resourceId(), updated.timestamp(),
                    updated.payload());
            if (!recomputed.equals(recordHashBefore)) {
                throw new IllegalStateException(
                        "Redaction would change recordHash for sequence " + sequence + " — refusing to apply");
            }

            records.set((int) sequence, updated);
            return updated;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Marks every non-archived record older than {@code retentionWindow} (measured from
     * its timestamp to now) as archived. Archival is a lifecycle flag only: it never
     * touches payload, previousHash, or recordHash, so it cannot introduce a chain break.
     *
     * @return the number of records newly archived by this call
     */
    public int applyRetention(Duration retentionWindow) {
        lock.lock();
        try {
            Instant cutoff = Instant.now().minus(retentionWindow);
            int archivedCount = 0;
            for (int i = 0; i < records.size(); i++) {
                EventRecord record = records.get(i);
                if (record.archived() || record.timestamp().isAfter(cutoff)) {
                    continue;
                }
                EventRecord archived = new EventRecord(
                        record.sequence(),
                        record.eventType(),
                        record.actorId(),
                        record.resourceType(),
                        record.resourceId(),
                        record.payload(),
                        record.timestamp(),
                        record.previousHash(),
                        record.recordHash(),
                        true,
                        Instant.now()
                );
                records.set(i, archived);
                archivedCount++;
            }
            return archivedCount;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Verifies the integrity of the entire chain by recomputing every record's hash from
     * its current (possibly redacted) payload commitments and comparing it to the stored
     * value. Archived records are verified identically to active ones — archival never
     * changes what gets hashed, so a legitimately archived record can never register as a
     * false-positive break. Returns the sequence number of the first broken link, or empty
     * if the chain is intact.
     */
    public Optional<Long> verifyChain() {
        lock.lock();
        try {
            String expectedPrevious = GENESIS_HASH;
            for (EventRecord record : records) {
                if (!expectedPrevious.equals(record.previousHash())) {
                    return Optional.of(record.sequence());
                }
                String recomputed = computeHash(
                        record.previousHash(),
                        record.sequence(),
                        record.eventType(),
                        record.actorId(),
                        record.resourceType(),
                        record.resourceId(),
                        record.timestamp(),
                        record.payload()
                );
                if (!recomputed.equals(record.recordHash())) {
                    return Optional.of(record.sequence());
                }
                expectedPrevious = record.recordHash();
            }
            return Optional.empty();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Returns all records matching {@code resourceId} and/or {@code actorId} (at least one
     * must be non-null), in sequence order, together with enough chain metadata for a
     * recipient to verify the slice independently. See {@link com.anthropic.audit.api.dto.ExportBundle}
     * for the verification contract.
     */
    public ExportResult exportRecords(String resourceId, String actorId) {
        if (resourceId == null && actorId == null) {
            throw new IllegalArgumentException("At least one of resourceId or actorId is required");
        }
        lock.lock();
        try {
            List<EventRecord> matched = records.stream()
                    .filter(r -> resourceId == null || resourceId.equals(r.resourceId()))
                    .filter(r -> actorId == null || actorId.equals(r.actorId()))
                    .toList();

            String precedingHash = matched.isEmpty() ? GENESIS_HASH : matched.get(0).previousHash();
            String chainHeadHash = records.isEmpty() ? GENESIS_HASH : records.get(records.size() - 1).recordHash();
            long chainLength = records.size();

            return new ExportResult(matched, precedingHash, chainHeadHash, chainLength);
        } finally {
            lock.unlock();
        }
    }

    private String hashValue(Object value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(canonicalJson(value).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException | com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("Failed to hash payload field value", e);
        }
    }

    private String canonicalJson(Object value) throws com.fasterxml.jackson.core.JsonProcessingException {
        return objectMapper.writeValueAsString(sortKeysDeep(value));
    }

    /**
     * Recursively converts maps into TreeMaps so that field ordering never affects the
     * resulting JSON string, and therefore never affects the hash.
     */
    @SuppressWarnings("unchecked")
    private Object sortKeysDeep(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> sorted = new TreeMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                sorted.put(String.valueOf(entry.getKey()), sortKeysDeep(entry.getValue()));
            }
            return sorted;
        }
        if (value instanceof List<?> list) {
            return list.stream().map(this::sortKeysDeep).toList();
        }
        return value;
    }

    private String computeHash(String previousHash, long sequence, String eventType, String actorId,
                                String resourceType, String resourceId, Instant timestamp,
                                Map<String, PayloadField> payload) {
        String payloadCommitment = computePayloadCommitment(payload);
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Failed to compute record hash", e);
        }
        StringBuilder canonical = new StringBuilder()
                .append(previousHash).append('|')
                .append(sequence).append('|')
                .append(eventType).append('|')
                .append(actorId).append('|')
                .append(resourceType).append('|')
                .append(resourceId).append('|')
                .append(timestamp).append('|')
                .append(payloadCommitment);
        byte[] hash = digest.digest(canonical.toString().getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(hash);
    }

    /**
     * The payload commitment is a hash over {@code fieldName:contentHash} pairs, sorted by
     * field name for determinism. It depends only on field names and each field's
     * content-hash — never on the current (possibly redacted) value — which is precisely
     * what allows values to be redacted after the fact without changing this commitment.
     */
    private String computePayloadCommitment(Map<String, PayloadField> payload) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            TreeMap<String, PayloadField> sorted = new TreeMap<>(payload);
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, PayloadField> entry : sorted.entrySet()) {
                sb.append(entry.getKey()).append(':').append(entry.getValue().contentHash()).append(';');
            }
            byte[] hash = digest.digest(sb.toString().getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Failed to compute payload commitment", e);
        }
    }

    /**
     * Test-support only: overwrites a record's timestamp and re-derives its recordHash to
     * match, as if the record had genuinely been ingested at that earlier instant. There is
     * no equivalent production capability — real timestamps are always
     * {@link Instant#now()} at {@link #append} — this exists solely so tests can construct
     * an "old enough to archive" record without corrupting its hash in the process.
     */
    EventRecord backdateForTesting(long sequence, Instant timestamp) {
        lock.lock();
        try {
            EventRecord record = records.get((int) sequence);
            String recomputedHash = computeHash(record.previousHash(), record.sequence(), record.eventType(),
                    record.actorId(), record.resourceType(), record.resourceId(), timestamp, record.payload());
            EventRecord backdated = new EventRecord(
                    record.sequence(),
                    record.eventType(),
                    record.actorId(),
                    record.resourceType(),
                    record.resourceId(),
                    record.payload(),
                    timestamp,
                    record.previousHash(),
                    recomputedHash,
                    record.archived(),
                    record.archivedAt()
            );
            records.set((int) sequence, backdated);
            if ((int) sequence + 1 < records.size()) {
                relinkFollowingRecordsForTesting((int) sequence);
            }
            return backdated;
        } finally {
            lock.unlock();
        }
    }

    private void relinkFollowingRecordsForTesting(int fromIndex) {
        for (int i = fromIndex + 1; i < records.size(); i++) {
            EventRecord previous = records.get(i - 1);
            EventRecord record = records.get(i);
            String recomputedHash = computeHash(previous.recordHash(), record.sequence(), record.eventType(),
                    record.actorId(), record.resourceType(), record.resourceId(), record.timestamp(),
                    record.payload());
            records.set(i, new EventRecord(
                    record.sequence(),
                    record.eventType(),
                    record.actorId(),
                    record.resourceType(),
                    record.resourceId(),
                    record.payload(),
                    record.timestamp(),
                    previous.recordHash(),
                    recomputedHash,
                    record.archived(),
                    record.archivedAt()
            ));
        }
    }

    public record PageResult(List<EventRecord> content, long totalElements) {
    }

    public record ExportResult(List<EventRecord> records, String precedingHash, String chainHeadHash,
                                long chainLength) {
    }
}
