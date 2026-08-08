package com.anthropic.audit.api;

import com.anthropic.audit.api.dto.CreateEventRequest;
import com.anthropic.audit.api.dto.EventResponse;
import com.anthropic.audit.api.dto.ExportBundle;
import com.anthropic.audit.api.dto.PageResponse;
import com.anthropic.audit.api.dto.RedactFieldRequest;
import com.anthropic.audit.api.dto.RetentionApplyRequest;
import com.anthropic.audit.api.dto.RetentionApplyResponse;
import com.anthropic.audit.api.dto.VerifyChainResponse;
import com.anthropic.audit.model.EventRecord;
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
 * <p>Intentionally exposes no PUT, PATCH, or generic DELETE mapping anywhere in this
 * controller — {@link EventStore} has no method capable of rewriting or removing an
 * existing record's content, sequence, or hash. The only endpoints that touch existing
 * records are {@code /events/{sequence}/redact} (clears one payload field's value while
 * preserving its hash commitment) and {@code /events/retention/apply} (flags records as
 * archived without altering payload or hashes). Both are additive, hash-preserving
 * operations, not mutation in the sense the chain is designed to detect.
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

    /**
     * Recomputes the entire chain from stored content and reports whether it is intact.
     * Archived and redacted records are verified exactly like any other record — neither
     * archival nor redaction can cause a false-positive break here, by construction (see
     * {@link EventStore}).
     */
    @GetMapping("/verify")
    public VerifyChainResponse verify() {
        return eventStore.verifyChain()
                .map(VerifyChainResponse::brokenAt)
                .orElseGet(VerifyChainResponse::ok);
    }

    /**
     * Redacts one payload field on one record. The field's value is cleared but its
     * content-hash commitment is preserved, so recordHash is unchanged and the chain
     * stays verifiable. See {@link EventStore#redactField} for the full rationale.
     */
    @PostMapping("/{sequence}/redact")
    public EventResponse redact(@PathVariable long sequence, @Valid @RequestBody RedactFieldRequest request) {
        EventRecord updated = eventStore.redactField(sequence, request.field(), request.reason());
        return EventResponse.from(updated);
    }

    /**
     * Archives every non-archived record older than the given retention window. Archival
     * is a lifecycle flag only — it does not modify payload, previousHash, or recordHash —
     * so it can never cause {@link #verify} to report a break.
     */
    @PostMapping("/retention/apply")
    public RetentionApplyResponse applyRetention(@Valid @RequestBody RetentionApplyRequest request) {
        int archivedCount = eventStore.applyRetention(request.retentionWindow());
        return new RetentionApplyResponse(archivedCount);
    }

    /**
     * Exports all records for a given resourceId and/or actorId as a self-contained,
     * independently verifiable bundle. See {@link ExportBundle} for the verification
     * contract a recipient can apply without live access to the full store.
     */
    @GetMapping("/export")
    public ExportBundle export(
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String actorId
    ) {
        if (resourceId == null && actorId == null) {
            throw new IllegalArgumentException("At least one of resourceId or actorId is required");
        }
        EventStore.ExportResult result = eventStore.exportRecords(resourceId, actorId);
        return ExportBundle.from(resourceId, actorId, result);
    }
}
