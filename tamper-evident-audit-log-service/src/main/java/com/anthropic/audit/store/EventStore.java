package com.anthropic.audit.store;

import com.anthropic.audit.api.dto.CreateEventRequest;
import com.anthropic.audit.model.EventRecord;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Append-only, hash-chained event store.
 *
 * <p>Each record's {@code recordHash} is SHA-256 over the previous record's hash
 * concatenated with this record's own content (sequence, type, actor, resource,
 * payload, timestamp). This forms a hash chain: mutating or removing any historical
 * record breaks the hash of every subsequent record, making tampering detectable.
 *
 * <p>There is intentionally no update or delete method on this class — the only
 * mutating operation is {@link #append}. This is what "append-only" means at the
 * API level: the capability to modify history simply does not exist in the code.
 *
 * <p>Timestamps are server-assigned ({@link Instant#now()} at append time), not
 * accepted from callers, so that event history cannot be backdated or forged.
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

            String recordHash = computeHash(previousHash, sequence, request, timestamp);

            EventRecord record = new EventRecord(
                    sequence,
                    request.eventType(),
                    request.actorId(),
                    request.resourceType(),
                    request.resourceId(),
                    request.payload(),
                    timestamp,
                    previousHash,
                    recordHash
            );

            records.add(record);
            return record;
        } finally {
            lock.unlock();
        }
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
     * Verifies the integrity of the entire chain by recomputing every hash from
     * scratch and comparing it to the stored value. Returns the sequence number of
     * the first broken link, or empty if the chain is intact.
     */
    public java.util.Optional<Long> verifyChain() {
        lock.lock();
        try {
            String expectedPrevious = GENESIS_HASH;
            for (EventRecord record : records) {
                if (!expectedPrevious.equals(record.previousHash())) {
                    return java.util.Optional.of(record.sequence());
                }
                String recomputed = computeHash(
                        record.previousHash(),
                        record.sequence(),
                        new CreateEventRequest(
                                record.eventType(),
                                record.actorId(),
                                record.resourceType(),
                                record.resourceId(),
                                record.payload()
                        ),
                        record.timestamp()
                );
                if (!recomputed.equals(record.recordHash())) {
                    return java.util.Optional.of(record.sequence());
                }
                expectedPrevious = record.recordHash();
            }
            return java.util.Optional.empty();
        } finally {
            lock.unlock();
        }
    }

    private String computeHash(String previousHash, long sequence, CreateEventRequest request, Instant timestamp) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            StringBuilder canonical = new StringBuilder()
                    .append(previousHash).append('|')
                    .append(sequence).append('|')
                    .append(request.eventType()).append('|')
                    .append(request.actorId()).append('|')
                    .append(request.resourceType()).append('|')
                    .append(request.resourceId()).append('|')
                    .append(timestamp).append('|')
                    .append(objectMapper.writeValueAsString(request.payload()));
            byte[] hash = digest.digest(canonical.toString().getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException | com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalStateException("Failed to compute record hash", e);
        }
    }

    public record PageResult(List<EventRecord> content, long totalElements) {
    }
}
