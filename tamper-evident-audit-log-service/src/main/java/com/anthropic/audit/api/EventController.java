package com.anthropic.audit.api;

import com.anthropic.audit.api.dto.CreateEventRequest;
import com.anthropic.audit.api.dto.EventResponse;
import com.anthropic.audit.api.dto.PageResponse;
import com.anthropic.audit.store.EventQuery;
import com.anthropic.audit.store.EventStore;
import jakarta.validation.Valid;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;

/**
 * Append-only audit event API.
 *
 * <p>Intentionally exposes only POST (ingest) and GET (query) — there is no PUT,
 * PATCH, or DELETE mapping anywhere in this controller, and {@link EventStore} has
 * no method capable of mutating or removing an existing record. This is enforced
 * structurally, not just by convention.
 */
@RestController
@RequestMapping("/events")
public class EventController {

    private final EventStore eventStore;

    public EventController(EventStore eventStore) {
        this.eventStore = eventStore;
    }

    @PostMapping
    public ResponseEntity<EventResponse> ingest(@Valid @RequestBody CreateEventRequest request) {
        var record = eventStore.append(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(EventResponse.from(record));
    }

    @GetMapping
    public PageResponse<EventResponse> query(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceType,
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ) {
        if (page < 0) {
            throw new IllegalArgumentException("page must be >= 0");
        }
        if (size < 1 || size > 500) {
            throw new IllegalArgumentException("size must be between 1 and 500");
        }
        if (from != null && to != null && from.isAfter(to)) {
            throw new IllegalArgumentException("from must not be after to");
        }

        EventQuery query = new EventQuery(actorId, resourceType, resourceId, eventType, from, to);
        EventStore.PageResult result = eventStore.query(query, page, size);

        List<EventResponse> content = result.content().stream()
                .map(EventResponse::from)
                .toList();

        return PageResponse.of(content, page, size, result.totalElements());
    }
}
