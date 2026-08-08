package com.anthropic.audit.store;

import java.time.Instant;

/**
 * Filter criteria for querying events. Any field left null is not filtered on.
 */
public record EventQuery(
        String actorId,
        String resourceType,
        String resourceId,
        String eventType,
        Instant from,
        Instant to
) {
}
