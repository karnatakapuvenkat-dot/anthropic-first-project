package com.anthropic.audit.api.dto;

import com.anthropic.audit.model.EventRecord;

import java.time.Instant;
import java.util.Map;

public record EventResponse(
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
    public static EventResponse from(EventRecord record) {
        return new EventResponse(
                record.sequence(),
                record.eventType(),
                record.actorId(),
                record.resourceType(),
                record.resourceId(),
                record.payload(),
                record.timestamp(),
                record.previousHash(),
                record.recordHash()
        );
    }
}
