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
| `GET /events/account-access-audit?resourceId=&actorId=` | Regulatory audit trail for client account data (see below) |

---

# Regulatory access audit

Product's raw ask: **"Regulators need to be able to audit access to client account data."**
Every load-bearing word in that sentence is underspecified. Below is the requirement as
clarified before any code was written, the ambiguities that clarification resolved, the
resulting design, and what was deliberately left out.

## Ambiguities identified and resolutions

The raw requirement doesn't say what "access" includes, what "client account data" is
scoped to, who actually calls the capability, or what "audit" needs to prove. I treated
each as a real fork rather than picking a silent default:

1. **Does "access" mean reads only, or reads and writes?** "Audit access" colloquially
   suggests "who looked at this," but the regulatory concerns this kind of requirement
   usually protects against (unauthorized viewing *and* unauthorized modification of client
   funds/data) cover both. **Resolved: both reads and writes are in scope** — the audit
   trail doesn't distinguish access-to-view from access-to-modify at the endpoint level;
   `eventType` (already free-text, e.g. `ACCOUNT_VIEWED` vs. `ACCOUNT_BALANCE_UPDATED`)
   carries that distinction for whoever reads the log.

2. **Does a regulator call an API directly, or does someone act as an intermediary?**
   This service has no authentication or authorization layer today — no login, no roles,
   no session model. Standing up regulator-specific identity and access control is a
   substantially larger project than "add an audit capability," and nothing in the ask
   implies it's in scope. **Resolved: this is a compliance-officer-mediated capability** —
   a person with existing access to this system queries it and produces evidence (a report
   or an exported bundle) to hand to a regulator. Direct regulator login is out of scope,
   documented explicitly below rather than silently assumed.

3. **What counts as "client account data"?** The event schema already has a free-text
   `resourceType` field; the existing test suite and examples use `"ACCOUNT"` for it.
   Reaching further — e.g. correlating an account with related transactions, statements, or
   KYC documents under one "client" — would need a client/customer identity concept this
   system doesn't have (`resourceId` today names one resource, not a person or
   organization). **Resolved: scoped to `resourceType == "ACCOUNT"`.** Cross-resource-type
   correlation is named explicitly as future work, not guessed at.

4. **What does "audit" need to prove?** Two very different bars: (a) a trustworthy record
   that access happened, who did it, and when; versus (b) an assertion that every access
   was *authorized*, which requires cross-referencing against a permissions/roles model.
   This service has no permission model to check against. **Resolved: (a) only** — this
   capability proves the existence and tamper-evidence of the access record; judging
   whether a given access was authorized is left to the humans reading the log (compliance
   officer, regulator), the same way it already works for every other event type this
   service stores.

## Clarified requirement statement

> The audit log service must let a compliance officer retrieve a complete, tamper-evident
> record of every read or write event recorded against resources of type `ACCOUNT`,
> filterable by account (`resourceId`) and/or by actor (`actorId`), optionally bounded to a
> time window, suitable for producing evidence to hand to a regulator. This is a read/query
> capability layered on the existing event log — it does not grant regulators direct system
> access, does not correlate access events against a permission model to judge whether each
> access was authorized, and does not unify account data with other resource types under a
> client/customer identity, since no such identity concept exists in this system today.

## Design

The existing `GET /events` endpoint already supports filtering by `resourceType`,
`resourceId`, `actorId`, and a time range — the underlying capability (query events by
account) already existed. What was missing was a **purpose-built, scoped-by-construction**
entry point: today, nothing stops a caller from either querying too broadly (no account
data filter enforced) or having to know and correctly supply `resourceType=ACCOUNT` by
convention on every regulator-facing request, with no guarantee that convention is
followed.

`GET /events/account-access-audit` (`EventController`) is a thin, deliberately narrow
wrapper:

- **`resourceType` is hardcoded to `"ACCOUNT"`**, not caller-suppliable — even if a caller
  passes `resourceType=DOCUMENT` on the query string, it's ignored (see
  `EventControllerTest.accountAccessAuditCannotBeUsedToBypassResourceTypeScoping`). This is
  the actual point of a separate endpoint rather than documentation telling callers to
  remember the right query parameter.
- **At least one of `resourceId` or `actorId` is required** (400 otherwise), so the
  endpoint can't be used to dump the entire account population in one call — a regulator
  audit request is, in practice, always about a specific account or a specific actor's
  activity, never "show me everything."
- **Reuses `EventStore.query` and `EventQuery` unchanged** — no new storage mechanism, no
  new event schema. `eventType` is deliberately left as a normal, unfiltered field in the
  response so a read (`ACCOUNT_VIEWED`) and a write (`ACCOUNT_BALANCE_UPDATED`) both surface
  under the same query, satisfying the "reads and writes" resolution above without the
  endpoint needing to know which event types are reads vs. writes.
- **Pairs with the existing `GET /events/export`** for the actual regulator hand-off
  artifact: `account-access-audit` is the *review* surface (a compliance officer paging
  through results, narrowing by actor/time), while `export?resourceId=...` produces the
  self-contained, independently verifiable bundle that's the actual evidence document —
  no new export mechanism was built, since the existing one already does exactly what's
  needed once the account has been identified via the audit query.

## Scope: implemented vs. explicitly deferred

**Implemented:**
- `GET /events/account-access-audit` — scoped, guarded query endpoint for account-type
  read/write events, by account and/or actor, optionally time-bounded.
- Full test coverage: 400 on no filter, correct account-only scoping (excluding same-`resourceId`-different-`resourceType`
  records), both-reads-and-writes inclusion, actor-based filtering across accounts, and
  confirmation the endpoint can't be tricked into a different `resourceType` via query
  parameter.

**Explicitly scoped out, and why:**
- **Direct regulator authentication/authorization.** This system has no auth layer at all
  today; adding one is an orders-of-magnitude larger change than this requirement asked
  for, and the ask itself doesn't specify an identity provider, session model, or
  permission granularity to build against. A compliance officer with existing system access
  is the mediating party instead.
- **Correlating access against an authorization model** ("was this access allowed").
  Requires a permissions/roles system that doesn't exist in this codebase. This capability
  proves *what happened*, not *whether it should have*.
- **Cross-resource-type correlation under a client identity** (account + transactions +
  KYC documents, unified). Requires a client/customer identity concept this schema doesn't
  have (`resourceId` names one resource, not a person). Noted as a natural next step if a
  future requirement needs "everything touching client X," not guessed at now.
- **Configurable/multi-value account resourceType.** `ACCOUNT_RESOURCE_TYPE` is a single
  hardcoded constant, not an externalized list. Changing or extending it is a one-line
  code change; making it configurable now would be speculative generality for a
  requirement that has named exactly one data category.
- **Enforcement that upstream systems actually emit account-access events.** This service
  can only audit what's logged to it — whether the system(s) that actually serve account
  data reliably call `POST /events` for every read and write is an integration contract
  outside this service's boundary, not something it can verify or enforce from the audit
  log side.
