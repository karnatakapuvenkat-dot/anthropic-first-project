package com.anthropic.audit.api.dto;

import com.anthropic.audit.store.EventStore;

import java.time.Instant;
import java.util.List;

/**
 * A self-contained, independently verifiable export of every record matching a
 * {@code resourceId} and/or {@code actorId} filter.
 *
 * <h2>What "independently verifiable" means here</h2>
 * A recipient who has only this bundle (no live access to the full store) can check two
 * things without trusting the exporter:
 * <ol>
 *   <li><b>Internal consistency</b>: recompute each record's {@code recordHash} from its
 *       own content, and confirm {@code records[i].previousHash == records[i-1].recordHash}
 *       for every {@code i > 0}, and {@code records[0].previousHash == precedingHash}.
 *       This proves the exported slice is an unbroken, contiguous run of the original
 *       chain — nothing in the middle was dropped, reordered, or altered after export.</li>
 *   <li><b>Placement within the larger chain</b> (weaker, advisory-only guarantee):
 *       {@code precedingHash} is the hash the first exported record chained from, and
 *       {@code chainHeadHash}/{@code chainLength} describe the full store's state at
 *       export time. These let a recipient who <i>separately</i> obtains the store's
 *       published head hash (e.g. from a trusted channel, a periodic public attestation)
 *       confirm this bundle is consistent with that broader chain, and wasn't spliced
 *       together from a forged history. Without such an independent reference point, an
 *       attacker controlling the whole store could still forge a self-consistent bundle —
 *       this bundle alone provides tamper-evidence for its own contents, not a trust root
 *       for the exporting system itself.</li>
 * </ol>
 *
 * <p>Records are included exactly as they exist in the store, including any redaction
 * tombstones and archived flags — verification recomputes hashes over the field
 * commitments described in {@link EventStore}, so redacted/archived records verify
 * successfully like any other.
 */
public record ExportBundle(
        Instant exportedAt,
        String resourceId,
        String actorId,
        String precedingHash,
        String chainHeadHash,
        long chainLength,
        List<EventResponse> records
) {
    public static ExportBundle from(String resourceId, String actorId, EventStore.ExportResult result) {
        return new ExportBundle(
                Instant.now(),
                resourceId,
                actorId,
                result.precedingHash(),
                result.chainHeadHash(),
                result.chainLength(),
                result.records().stream().map(EventResponse::from).toList()
        );
    }
}
