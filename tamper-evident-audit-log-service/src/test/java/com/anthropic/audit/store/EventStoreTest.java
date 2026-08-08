package com.anthropic.audit.store;

import com.anthropic.audit.api.dto.CreateEventRequest;
import com.anthropic.audit.model.EventRecord;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
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
                tampered.recordHash() // stale hash, no longer matches content
        );
        internalRecords.set(1, forged);

        assertEquals(1L, store.verifyChain().orElseThrow());
    }

    @Test
    void noPublicMethodCanMutateOrDeleteAnExistingRecord() {
        for (var method : EventStore.class.getDeclaredMethods()) {
            if (!Modifier.isPublic(method.getModifiers())) {
                continue;
            }
            String name = method.getName().toLowerCase();
            assertFalse(name.contains("update"), "Unexpected mutating method: " + method.getName());
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
}
