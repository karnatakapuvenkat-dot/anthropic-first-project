# Retention, Redaction, and Export — Design Notes

This extends the tamper-evident audit log with three capabilities: retention/archival,
structured field-level redaction, and self-contained bulk export. The interesting problem
is redaction: the original design hashed the payload as one JSON blob, so clearing a
sensitive value would change the bytes that went into `recordHash` and make every
verification after that point report a break. This document explains the scheme used to
avoid that, along with its trade-offs and limitations.

## Redaction: field-commitment hashing

### The problem

`recordHash` must keep proving "this record's content has not changed since ingestion."
But "content" for a payload field with sensitive data needs to become "absence of the
value, on purpose" at some point, without that transition looking like tampering.

### The scheme

Instead of hashing the payload as a single JSON blob, each payload field is hashed
**independently** at ingestion time:

```
contentHash(field) = SHA256(canonicalJson(field.value))
```

`canonicalJson` sorts object keys recursively so that field ordering never affects the
hash. This per-field hash is stored permanently on the record, alongside the value, as a
`PayloadField { value, contentHash, redacted, redactedAt, redactionReason }`.

The record's **payload commitment** — the thing that actually feeds into `recordHash` — is
computed from the sorted list of `fieldName:contentHash` pairs, not from the values
themselves:

```
payloadCommitment = SHA256( "amount:0604cd31...;accountNumber:9f191b31...;" )
recordHash = SHA256( previousHash | sequence | eventType | actorId |
                      resourceType | resourceId | timestamp | payloadCommitment )
```

**Redacting a field** (`EventStore.redactField`) clears `value` to `null` but leaves
`contentHash` untouched. Because the payload commitment is a function of field names and
content-hashes only, it recomputes identically before and after redaction — so
`recordHash` doesn't change, and `verifyChain()` keeps passing. This is the same idea a
Merkle tree uses to prove a leaf existed without revealing it: the hash is a *commitment*
to the value, and the commitment survives the value's removal. `EventStore.redactField`
double-checks this invariant defensively — it recomputes the hash after mutating the field
and throws `IllegalStateException` (mapped to 500) if it doesn't match, so an accidental
change to the commitment formula fails loudly at redaction time rather than silently
breaking the chain later.

`GET /events/verify` requires no special case for redacted records: it always recomputes
from whatever is currently stored (`value` or the tombstone), so a legitimately redacted
field is indistinguishable, at the verification level, from a field that was never
redacted in the first place — both produce a matching hash.

### Trade-offs considered

- **Encrypt instead of hash-and-clear.** Store `Enc(value)` and hash the ciphertext;
  "redaction" becomes destroying the encryption key. This gives cryptographic (not just
  procedural) irreversibility and is the standard answer for GDPR-style "crypto-shredding."
  I didn't take this path because it adds real key-management surface (a KMS, key
  rotation, per-tenant keys) that's disproportionate to what this exercise is testing, and
  it doesn't change the core hashing problem — you'd still need a per-field commitment
  scheme underneath so that destroying one key doesn't invalidate hashes for unrelated
  fields on the same record. The scheme here is the piece that's independent of whichever
  redaction backend you choose; swapping "clear the value" for "destroy the key that
  decrypts the value" is a small change on top of it.
- **Merkle tree over payload fields**, with redaction supplying an inclusion proof instead
  of a flat commitment list. Equivalent security properties for this use case (a payload
  with a handful of fields) but more moving parts and code for no practical benefit at this
  scale. Worth revisiting if payloads grow to have many fields and partial-proof bundles
  (proving one field without shipping all the others' hashes) become valuable.
- **Redact the whole record, not per-field.** Simpler, but conflates retention (a lifecycle
  concern — "this event is old") with privacy (a data concern — "this specific value must
  go away"). Real audit records usually have a mix of sensitive and non-sensitive fields in
  the same payload (e.g. `eventType: PAYMENT_PROCESSED`, `amount: 500` — useful for
  compliance review — alongside `accountNumber` — sensitive); collapsing them would destroy
  audit value unnecessarily.
- **Versioned hash scheme** (a `hashVersion` field, with old records verified under a v1
  algorithm and new records under v2). Rejected for this exercise since there's no
  persisted production data to be backward-compatible with — the store is in-memory and
  this is a from-scratch redesign of the hashing scheme. In a system with real historical
  data, this is the honest way to introduce field-commitment hashing without a "rehash
  everything" migration.

### Limitations

- **`contentHash` is not a secrecy guarantee for low-entropy fields.** It's a plain,
  unsalted SHA-256 digest. For a field like a 4-digit PIN or a boolean, someone who obtains
  `contentHash` can brute-force the original value by hashing candidates — there are only
  10,000 possibilities for a PIN. This is fine for high-entropy values (account numbers,
  SSNs, UUIDs) where brute-forcing the hash is infeasible, but a field that's both
  low-entropy and sensitive would need a per-field random salt (stored alongside
  `contentHash`, itself immutable) to close this gap. I didn't add salting by default
  because it's one more piece of permanent per-field state for a problem that, in this
  service's actual field set (account numbers, personal identifiers), doesn't apply — but
  it's a one-line addition to `PayloadField` and `hashValue` if a low-entropy field ever
  needs redacting.
- **Redaction is one-way at the store level.** Once `value` is cleared, `EventStore` has no
  way to recover it — there's no soft-delete-of-the-redaction. This is intentional (the
  whole point is that the data is gone), but it means a mistaken redaction can't be undone
  through this API; only re-ingestion of a new corrective event can address it, which
  itself becomes part of the audit trail (arguably a feature, not a limitation).
- **Field names are never redactable, only values.** If a field's *name* is itself
  sensitive (e.g. a key like `patientDiagnosisCode` used as a literal payload key rather
  than a value), this scheme doesn't hide it — the payload commitment includes field names
  in the clear. Sensitive facts should be stored as values under a neutral key, not as keys
  themselves.
- **No support for "redact and then prove what was there" (selective disclosure).** A
  recipient of a redacted record sees only that some value existed with a certain
  `contentHash` — they can't reconstruct it, and there's no accompanying zero-knowledge
  proof of properties of the redacted value (e.g. "the amount was over $10,000" without
  revealing the exact amount). Out of scope here; would be the next layer if a compliance
  requirement needed it.

## Retention and archival

`POST /events/retention/apply` takes a caller-supplied `retentionWindow` (ISO-8601
duration, e.g. `P90D`) and marks every non-archived record whose timestamp is older than
`now - retentionWindow` as `archived = true`, stamping `archivedAt`. It's on-demand rather
than a background sweep, matching this service's synchronous, in-memory design — an
operator or scheduler calls it when they want retention policy applied.

Archival is **only** a lifecycle flag. It never touches `payload`, `previousHash`, or
`recordHash`. This is what makes the "no false-positive break for archived records"
requirement trivially true rather than something `verifyChain()` has to special-case:
archival doesn't change anything that verification recomputes, so an archived record
verifies exactly like an active one. Retention and redaction are deliberately separate
mechanisms — archiving a batch of old records doesn't, by itself, remove any sensitive
data; a retention *policy* that wants both would call archival and then redact specific
fields on the now-archived records, using the redaction endpoint.

**Trade-off**: an on-demand endpoint means retention isn't enforced automatically — nothing
stops a caller from never invoking it. A production system would likely pair this with a
scheduled job (or trigger it from `applyRetention` on a fixed interval via
`@Scheduled`), which was left out here to keep the store's concurrency model simple (one
lock, no background threads) and because "how retention gets triggered" is an operational
decision, not a data-model one — the endpoint is the primitive; scheduling is layered on
top.

## Bulk export

`GET /events/export?resourceId=...&actorId=...` (at least one required) returns every
matching record in sequence order as an `ExportBundle`:

```json
{
  "exportedAt": "...",
  "resourceId": "acct-1",
  "actorId": null,
  "precedingHash": "<previousHash of the first exported record>",
  "chainHeadHash": "<recordHash of the last record in the whole store>",
  "chainLength": 3,
  "records": [ ... ]
}
```

### What a recipient can verify, and what they can't

With only the bundle in hand (no live access to the store), a recipient can:

1. **Recompute each record's `recordHash`** from its own content (including any
   redaction tombstones or archived flags, which verify identically to normal fields —
   see above) and confirm it matches the stored value.
2. **Confirm internal linkage**: `records[i].previousHash == records[i-1].recordHash` for
   every `i > 0`, and `records[0].previousHash == precedingHash`. This proves the exported
   slice is a contiguous, unbroken run of the original chain — nothing from the middle of
   this resource's history was quietly dropped, reordered, or altered after export.

`precedingHash`, `chainHeadHash`, and `chainLength` exist for a **weaker, advisory**
guarantee: if a recipient separately obtains the store's true head hash through a trusted
channel (e.g. a periodically published attestation, or a request straight to the source),
they can confirm this bundle's `chainHeadHash`/`chainLength` matches what the full chain
looked like at export time — evidence the bundle wasn't spliced together from a forged or
rolled-back history.

### Limitation

Without an independently obtained reference to the true chain head, bundle-only
verification (point 1 and 2 above) cannot rule out a scenario where the entire exporting
system is compromised and fabricates a self-consistent forged chain from scratch — the
bundle proves internal consistency, not that the source system itself is honest. Closing
that gap needs an external anchor (e.g. periodically publishing `chainHeadHash` to an
append-only public log or a third party), which is out of scope for this service but is
the natural next step if bundles need to be verifiable against a party who doesn't trust
the exporter at all.

## API summary

| Endpoint | Purpose |
|---|---|
| `POST /events` | Ingest an event (unchanged from Scenario A) |
| `GET /events` | Query/paginate events (unchanged from Scenario A) |
| `GET /events/verify` | Recompute and verify the entire chain |
| `POST /events/{sequence}/redact` | Clear one payload field's value, preserving its hash commitment |
| `POST /events/retention/apply` | Archive records older than a given retention window |
| `GET /events/export?resourceId=&actorId=` | Export a self-contained, independently verifiable bundle |
