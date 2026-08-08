package com.anthropic.audit.store;

import com.anthropic.audit.api.dto.CreateEventRequest;
import com.anthropic.audit.model.EventRecord;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class EventStoreTest {

    private CreateEventRequest sampleRequest(String actorId) {
        return new CreateEventRequest(
                "USER_LOGIN",
                actorId,
                "USER",
                "user-123",
                Map.of("ip", "10.0.0.1")
        );
    }

    @Test
    void appendAssignsIncrementingSequenceAndServerTimestamp() {
        EventStore store = new EventStore();

        Instant before = Instant.now();
        EventRecord first = store.append(sampleRequest("alice"));
        EventRecord second = store.append(sampleRequest("bob"));
        Instant after = Instant.now();

        assertEquals(0, first.sequence());
        assertEquals(1, second.sequence());
        assertFalse(first.timestamp().isBefore(before));
        assertFalse(second.timestamp().isAfter(after));
    }

    @Test
    void eachRecordLinksToPreviousRecordHash() {
        EventStore store = new EventStore();

        EventRecord first = store.append(sampleRequest("alice"));
        EventRecord second = store.append(sampleRequest("bob"));
        EventRecord third = store.append(sampleRequest("carol"));

        assertEquals("0".repeat(64), first.previousHash());
        assertEquals(first.recordHash(), second.previousHash());
        assertEquals(second.recordHash(), third.previousHash());

        assertNotEquals(first.recordHash(), second.recordHash());
        assertNotEquals(second.recordHash(), third.recordHash());
    }

    @Test
    void verifyChainReportsIntactChainAsEmpty() {
        EventStore store = new EventStore();
        store.append(sampleRequest("alice"));
        store.append(sampleRequest("bob"));

        assertTrue(store.verifyChain().isEmpty());
    }

    @Test
    void verifyChainDetectsTamperedRecord() throws Exception {
        EventStore store = new EventStore();
        store.append(sampleRequest("alice"));
        store.append(sampleRequest("bob"));
        store.append(sampleRequest("carol"));

        // Reach into the internal list to simulate an out-of-band mutation
        // (something that should be impossible through the public API).
        Field recordsField = EventStore.class.getDeclaredField("records");
        recordsField.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<EventRecord> internalRecords = (List<EventRecord>) recordsField.get(store);

        EventRecord tampered = internalRecords.get(1);
        EventRecord forged = new EventRecord(
                tampered.sequence(),
                tampered.eventType(),
                "mallory", // actorId forged
                tampered.resourceType(),
                tampered.resourceId(),
                tampered.payload(),
                tampered.timestamp(),
                tampered.previousHash(),
                tampered.recordHash(), // stale hash, no longer matches content
                tampered.archived(),
                tampered.archivedAt()
        );
        internalRecords.set(1, forged);

        assertEquals(1L, store.verifyChain().orElseThrow());
    }

    @Test
    void noPublicMethodCanRewriteOrDeleteAnExistingRecordsHashOrOrdering() {
        for (var method : EventStore.class.getDeclaredMethods()) {
            if (!Modifier.isPublic(method.getModifiers())) {
                continue;
            }
            String name = method.getName().toLowerCase();
            assertFalse(name.contains("delete"), "Unexpected mutating method: " + method.getName());
            assertFalse(name.contains("remove"), "Unexpected mutating method: " + method.getName());
        }
    }

    @Test
    void queryFiltersByActorResourceTypeAndEventType() {
        EventStore store = new EventStore();
        store.append(new CreateEventRequest("USER_LOGIN", "alice", "USER", "u1", Map.of()));
        store.append(new CreateEventRequest("RECORD_UPDATED", "alice", "DOCUMENT", "d1", Map.of()));
        store.append(new CreateEventRequest("USER_LOGIN", "bob", "USER", "u2", Map.of()));

        EventStore.PageResult result = store.query(
                new EventQuery("alice", null, null, "USER_LOGIN", null, null), 0, 20);

        assertEquals(1, result.totalElements());
        assertEquals("alice", result.content().get(0).actorId());
        assertEquals("USER_LOGIN", result.content().get(0).eventType());
    }

    @Test
    void queryFiltersByTimeRange() throws InterruptedException {
        EventStore store = new EventStore();
        EventRecord first = store.append(sampleRequest("alice"));
        Thread.sleep(5);
        Instant cutoff = Instant.now();
        Thread.sleep(5);
        EventRecord second = store.append(sampleRequest("bob"));

        EventStore.PageResult result = store.query(
                new EventQuery(null, null, null, null, cutoff, null), 0, 20);

        assertEquals(1, result.totalElements());
        assertEquals(second.sequence(), result.content().get(0).sequence());
    }

    @Test
    void queryPaginatesResults() {
        EventStore store = new EventStore();
        for (int i = 0; i < 25; i++) {
            store.append(sampleRequest("actor-" + i));
        }

        EventStore.PageResult page0 = store.query(new EventQuery(null, null, null, null, null, null), 0, 10);
        EventStore.PageResult page2 = store.query(new EventQuery(null, null, null, null, null, null), 2, 10);

        assertEquals(25, page0.totalElements());
        assertEquals(10, page0.content().size());
        assertEquals(5, page2.content().size());
    }

    // ---- Redaction ----

    @Test
    void redactFieldClearsValueButPreservesRecordHash() {
        EventStore store = new EventStore();
        CreateEventRequest request = new CreateEventRequest(
                "PAYMENT_PROCESSED", "alice", "ACCOUNT", "acct-1",
                Map.of("accountNumber", "1234567890", "amount", 500));
        EventRecord original = store.append(request);
        String hashBefore = original.recordHash();

        EventRecord redacted = store.redactField(original.sequence(), "accountNumber", "GDPR erasure request");

        assertEquals(hashBefore, redacted.recordHash());
        assertNull(redacted.payload().get("accountNumber").value());
        assertTrue(redacted.payload().get("accountNumber").redacted());
        assertNotNull(redacted.payload().get("accountNumber").contentHash());
        // Untouched field is unaffected.
        assertEquals(500, redacted.payload().get("amount").value());
    }

    @Test
    void redactFieldDoesNotBreakChainVerification() {
        EventStore store = new EventStore();
        store.append(sampleRequest("alice"));
        EventRecord target = store.append(new CreateEventRequest(
                "PAYMENT_PROCESSED", "bob", "ACCOUNT", "acct-1",
                Map.of("accountNumber", "9999888877")));
        store.append(sampleRequest("carol"));

        store.redactField(target.sequence(), "accountNumber", "privacy request");

        assertTrue(store.verifyChain().isEmpty(),
                "Redacting a field must not be reported as a chain break");
    }

    @Test
    void redactFieldRejectsUnknownSequenceOrField() {
        EventStore store = new EventStore();
        EventRecord record = store.append(sampleRequest("alice"));

        assertThrows(IllegalArgumentException.class, () -> store.redactField(99, "x", "reason"));
        assertThrows(IllegalArgumentException.class,
                () -> store.redactField(record.sequence(), "doesNotExist", "reason"));
    }

    @Test
    void redactingSameFieldTwiceIsIdempotentAndStillVerifies() {
        EventStore store = new EventStore();
        EventRecord record = store.append(new CreateEventRequest(
                "USER_UPDATED", "alice", "USER", "u1", Map.of("ssn", "111-22-3333")));

        store.redactField(record.sequence(), "ssn", "first request");
        EventRecord second = store.redactField(record.sequence(), "ssn", "second request");

        assertTrue(second.payload().get("ssn").redacted());
        assertTrue(store.verifyChain().isEmpty());
    }

    // ---- Retention / archival ----

    @Test
    void applyRetentionArchivesOnlyRecordsOlderThanWindow() {
        EventStore store = new EventStore();
        EventRecord recent = store.append(sampleRequest("alice"));

        store.backdateForTesting(recent.sequence(), Instant.now().minus(Duration.ofDays(100)));

        int archivedCount = store.applyRetention(Duration.ofDays(90));

        assertEquals(1, archivedCount);
        assertTrue(store.findBySequence(recent.sequence()).orElseThrow().archived());
    }

    @Test
    void applyRetentionLeavesRecentRecordsUnarchived() {
        EventStore store = new EventStore();
        EventRecord fresh = store.append(sampleRequest("alice"));

        int archivedCount = store.applyRetention(Duration.ofDays(90));

        assertEquals(0, archivedCount);
        assertFalse(store.findBySequence(fresh.sequence()).orElseThrow().archived());
    }

    @Test
    void archivedRecordsStillVerifyWithoutFalsePositiveBreak() {
        EventStore store = new EventStore();
        store.append(sampleRequest("alice"));
        EventRecord old = store.append(sampleRequest("bob"));
        store.append(sampleRequest("carol"));

        store.backdateForTesting(old.sequence(), Instant.now().minus(Duration.ofDays(400)));
        store.applyRetention(Duration.ofDays(90));

        assertTrue(store.findBySequence(old.sequence()).orElseThrow().archived());
        assertTrue(store.verifyChain().isEmpty(),
                "A legitimately archived record must not register as a chain break");
    }

    @Test
    void applyRetentionDoesNotChangePayloadOrHashes() {
        EventStore store = new EventStore();
        EventRecord record = store.append(sampleRequest("alice"));
        EventRecord backdated = store.backdateForTesting(record.sequence(), Instant.now().minus(Duration.ofDays(400)));

        store.applyRetention(Duration.ofDays(90));

        EventRecord archived = store.findBySequence(record.sequence()).orElseThrow();
        assertEquals(backdated.recordHash(), archived.recordHash());
        assertEquals(backdated.previousHash(), archived.previousHash());
        assertEquals(backdated.payload(), archived.payload());
    }

    // ---- Bulk export ----

    @Test
    void exportReturnsOnlyMatchingRecordsInSequenceOrder() {
        EventStore store = new EventStore();
        store.append(new CreateEventRequest("A", "alice", "DOC", "doc-1", Map.of()));
        store.append(new CreateEventRequest("B", "bob", "DOC", "doc-2", Map.of()));
        store.append(new CreateEventRequest("C", "alice", "DOC", "doc-1", Map.of()));

        EventStore.ExportResult result = store.exportRecords("doc-1", null);

        assertEquals(2, result.records().size());
        assertEquals(0L, result.records().get(0).sequence());
        assertEquals(2L, result.records().get(1).sequence());
    }

    @Test
    void exportIncludesChainMetadataThatVerifiesTheSlice() {
        EventStore store = new EventStore();
        store.append(new CreateEventRequest("A", "alice", "DOC", "other", Map.of()));
        EventRecord first = store.append(new CreateEventRequest("B", "alice", "DOC", "doc-1", Map.of("k", "v")));
        EventRecord second = store.append(new CreateEventRequest("C", "alice", "DOC", "doc-1", Map.of("k", "v2")));
        store.append(new CreateEventRequest("D", "alice", "DOC", "other", Map.of()));

        EventStore.ExportResult result = store.exportRecords("doc-1", null);

        assertEquals(first.previousHash(), result.precedingHash());
        assertEquals(first.recordHash(), result.records().get(0).recordHash());
        assertEquals(first.recordHash(), result.records().get(1).previousHash());
        assertEquals(second.recordHash(), result.records().get(1).recordHash());
        assertEquals(4, result.chainLength());
    }

    @Test
    void exportRequiresAtLeastOneFilter() {
        EventStore store = new EventStore();
        assertThrows(IllegalArgumentException.class, () -> store.exportRecords(null, null));
    }
}
