# Session, storage and network recovery

## Classify a failure before acting

Temporary HTTPS/provider outage, stale session, changed station authority, missing STATE, corrupt root ledger and expired response have different recovery routes. The live exporter and beacon consumer must not coerce unknown evidence into an empty healthy role or new identity. Authentication/signature faults remain blocking until the intended identity is restored.

## Exact expired-session reconciliation

The station recovery endpoint receives a signed request containing exact pending session payload and journal digest. It returns bounded recovery evidence only for the same authorized unexpired/expired checkpoint situation under the host key lock. Unknown, revoked, superseded or unrelated request history refuses; the client restores only the saved session intent, not a new epoch guessed from local files.

## No automatic reset

Root-owned pending session/role markers, storage fsync requirements and held installation evidence are preserved through restart. Operator procedures can explicitly investigate and authorize supervised reconciliation; network transient errors alone do not justify resetting identity or replaying a controller command.

## Detailed contracts and original evidence

- [SESSION-RECOVERY.md](../SESSION-RECOVERY.md)
- [BEACON-SUPERVISOR.md](../BEACON-SUPERVISOR.md)
- [MANAGED-STATE.md](../MANAGED-STATE.md)

The live host, current companion revisions and exact approval gates require separate acceptance. Dated handoffs retain their historical status and do not become production authorization through editorial consolidation.
