package com.anthropic.audit.api.dto;

import com.anthropic.audit.model.EventRecord;

import java.time.Instant;
import java.util.Map;
import java.util.stream.Collectors;

public record EventResponse(
        long sequence,
        String eventType,
        String actorId,
        String resourceType,
        String resourceId,
        Map<String, PayloadFieldResponse> payload,
        Instant timestamp,
        String previousHash,
        String recordHash,
        boolean archived,
        Instant archivedAt
) {
    public static EventResponse from(EventRecord record) {
        return new EventResponse(
                record.sequence(),
                record.eventType(),
                record.actorId(),
                record.resourceType(),
                record.resourceId(),
                record.payload().entrySet().stream()
                        .collect(Collectors.toMap(Map.Entry::getKey, e -> PayloadFieldResponse.from(e.getValue()))),
                record.timestamp(),
                record.previousHash(),
                record.recordHash(),
                record.archived(),
                record.archivedAt()
        );
    }
}
