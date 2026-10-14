# Protected managed beacon supervisor, protocol v1

Host-discover 0.4.3 supplies the root supervisor and its UID970 client. Host-install
continues to own STATE preparation, identity authorization/consumption, mount
inspection and installer recovery holds. The supervisor does not change those
interfaces, open private keys, grant full admission, or dispatch controller actions.

## Provisioning and ownership

After the producer has explicitly prepared STATE and consumed the identity receipt,
a root administrator/installer may run:

```
host-discover-supervisor prepare --state-volume-id <exact configured STATE UUID>
```

This verifies live STATE and the current consumed receipt, then creates
`/state/host-discover-supervisor` root:root 0700. `lock` and `ledger.json` are
root:root 0600. No account or key is created. Repeating preparation is idempotent
only while its initial record is unchanged; it never resets an operated ledger.
No boot unit automatically invokes preparation. Missing state after provisioning
must not be recreated by a recurring installer service.

Use host-install 0.4.2 `beacon-stage` to compose the reviewed templates and
executable locations. Its persistent `serve-listen` and `state-admission-listen`
services remain available until beacon finishes during shutdown. Raw Accept=yes
templates are not the supported managed-beacon deployment: live reboot showed
that shutdown can prevent a newly activated handler from servicing clean finish.
The socket protocol is unchanged; each listener handles bounded connections
serially, with a 20-second request deadline. Invalid peers/requests close only
that connection. The composed consumer Requires/After both request services. The socket is
`/run/host-discover-supervisor/beacon.sock`, root:970 0660, below a root:root 0755
directory. Server requires kernel peer UID970; client requires kernel peer UID0
and checks directory/socket metadata without following symlinks. This is a separate
socket from host-install's read-only admission interface. There is no reset RPC.

The supervisor socket uses the corrected post-bootstrap ordering pattern, with
`DefaultDependencies=no` and explicit sysinit/STATE/identity/shutdown dependencies.
The beacon stops before its required sockets; mount loss binds their lifetime to
STATE. No automatic restart is configured. A full boot-graph regression includes
both sockets and the consumer, with a negative ordering-cycle control.

## Root-owned ledger

Schema 1 / kind `zog-beacon-supervisor` has exactly:

- `binding`: installation UUID, STATE UUID, consumed public fingerprint.
- `revision`: monotonic nonnegative transaction counter.
- `run`: null or `{id, bindings}`. Bindings are the producer-defined boot ID,
  bootstrap/marker digests and actual mounted device/inode.
- `fault`: null or bounded `{id, code}`. No caller-provided diagnostic text.
- `journal_sha256`: null only before initial journal preparation; otherwise SHA256
  of host-install canonical JSON encoding of the complete validated beacon journal.
- `reset`: null or the latest root-authorized retry `{id, run_id, reason}`.

Ledger mutations use an exclusive nonblocking root lock and fsynced pending/link/
replacement/directory writes. Pending or unknown files block every normal operation
and reset. This is bounded current state, not an unlimited audit log. Preserve the
ledger together with the host identity and beacon journal in recovery backups.

The root digest catches service-state loss/change against a separately protected
local record. It does not defeat rollback of the entire STATE disk, root compromise,
or a malicious process already possessing UID970's signing privileges. Independent
station epoch/checkpoint history detects one-sided rollback after session creation.
Before any station history exists, no external rollback witness is claimed.

## Authenticated local request

Canonical JSON, schema 1, kind `zog-beacon-supervisor-request`, exact fields:
`nonce`, `action`, `run_id`, `bindings`, `journal_sha256`, `code`.
The nonce is 32 random bytes encoded as 64 lowercase hex characters. Run ID is a
canonical UUID generated anew for the process. Only fixed actions are accepted:

| Action | Semantics |
|---|---|
| begin | Require no previous run/fault; durably record this active run before private journal preparation or network effects. Return protected journal digest. |
| check | Require matching active run/current boot/configuration/mount, no fault/installer hold, and matching journal digest. No write. |
| commit | Matching unheld run only; durably checkpoint a non-null digest after the consumer fsyncs its journal. Never clear a checkpoint. |
| finish | Matching healthy run/digest only; record a clean end. No trust or history change. |
| fault | Matching run only; latch a fixed fault code. Installer ledger health is not required, but verified mounted STATE is. |

Each normal action rereads producer admission. Fault reporting still requires live
STATE inspection. If it cannot be recorded, the already durable active-run record
blocks a later process. An unavailable supervisor never permits a request to proceed.
No action accepts file paths, keys, receipts, reset flags or control capabilities.
`code` is null except on fault, when only `managed-state-fault` or
`managed-transport-fault` is accepted. Requests/replies are bounded at 8192 bytes,
per-read timeout 5 seconds, with a 20-second service runtime limit.

Reply kind `zog-beacon-supervisor-response`, schema 1, echoes nonce and has `ok` plus
`result` or `code`. Successful result contains `binding`, `revision`,
`journal_sha256`, `run_id`, `transport_enabled:false`, `control_authorized:false`.
The client validates exact fields and bindings. An observation is not a lease.
The consumer checks again before and after outbound operations and durable writes.
A concurrently introduced hold cannot retract a request already sent.

## Explicit root retry/reset

Stop the beacon service and investigate the failure, then inspect:

```
host-discover-supervisor inspect
host-discover-supervisor reset --revision <observed revision> --run-id <observed run UUID> --reason '<operator reason>'
```

Reset requires root, healthy matching STATE/consumed identity, no installer hold,
the exact current revision/run, and acquisition of the consumer journal lock to
confirm no cooperating beacon is running. It preserves the journal digest, identity,
station pins and station checkpoints; it records the retry authorization and clears
only this supervisor's run/fault. It does not clear host-install recovery holds.
A stale command cannot reset a newer run. A service-account request cannot reset.

After a blocking fault, retry still requires this authorization. A classified
temporary network failure instead follows the automatic policy below, preserving
the existing pending session request. Expired unresolved responses, mismatching station history,
changed keys, missing journals, and partial/conflicting filesystem publications
remain blocked. Reset is not a repair command. Offline torn-write reconciliation,
authorized key/history transitions and whole-STATE disaster recovery need separate
reviewed operations; never delete markers or reset station rows to force admission.

## Consumer and station setup

`host-discover --managed-state` remains the unchanged narrow diagnostic.
`host-discover --managed-beacon [--once]` is an explicit additional profile. It
requires this provisioned supervisor, the existing producer socket, UID/GID970,
exactly one configured control registry, and the existing verified identity.
No legacy fallback, implicit key creation, archive delivery, password export,
mirror roles, remote inspection or lifecycle dispatch is reachable in this profile.

The beacon's actual trust/binding/session schema is the strict versioned
`control/managed.json` journal. It is descriptor-anchored, process-locked, revalidated
against disk and the root digest, and checked for registry/origin/identity/expected
UUID agreement before network access. The initial empty journal is created only
when the root ledger has never checkpointed one; a missing later journal blocks.
Reserved `trust`, `registries`, and `health` directories must remain empty; foreign
state requires explicit migration, rather than being silently ignored. Identity
schema validation belongs to host-identify's existing receipt-checked loader.
Controller state is not opened or declared compatible: this is beacon admission,
not full controller admission. Installer schema expectations are not evidence.

On the isolated station configure `HOST_MANAGED_ADMISSION_ENABLED=1`,
`HOST_MANAGED_AUTHORITY_ID`, `HOST_MANAGED_SIGNING_KEY_FILE`, and its HTTPS
`HOST_IDENTITY_ORIGIN`. Use a dedicated protected Ed25519 signing key, never an
archive or release-signing key. The default remains disabled. Normal migrations
must include 0012; this pass adds no database migration.

Enrollment uses TLS verification and host-signed requests, retaining explicit
fingerprint approval. The station public key is initially established through that
authenticated HTTPS exchange, then pinned in the protected-checkpointed journal.
There are no redirects, environment proxies, or TLS-verification bypasses. A fresh
signed station session is required for heartbeats on each process start; unresolved
pending sessions are reconciled first, even across a boot change, then replaced.
Each successful durable commit owns a separate copy of the journal data.

## Temporary network outages (0.4.3)

Only errors classified inside HTTPS connection/read operations permit automatic
retry: timeouts, connection failures (including refused/reset connections), remote
disconnects, incomplete reads, temporary DNS EAI_AGAIN, network/host unreachable or
network down, and HTTP 408, 429, 502, 503, 504. Other HTTP responses (including 401,
403, 409 and 500), TLS/certificate/protocol failures, invalid JSON/schema/signatures,
unknown DNS names and unclassified failures block. Local key, CA, journal, STATE,
admission socket and supervisor errors are never classified as network retries.

The process retains its active supervised run and durable pending request. It
checks local admission immediately after failure and before further work, clears
only the in-memory session cache, then waits with exponential backoff of roughly
2, 4, 8, 16, 32, 60 seconds (80–100% jitter), capped at 60 seconds. Attempts continue
until success, stop or a blocking fault. Success resets backoff. During both
backoff and ordinary 60-second waits, health is checked at intervals no longer than
5 seconds, excluding the time spent in each check. Network operations retain their
10-second socket timeout; this is not a hard total deadline against a slow peer.

An uncertain session request is retried with exactly its saved payload and a fresh
HTTP signature nonce. It is never replaced to evade station history. An expired
unresolved session response remains a blocking recovery case; no automatic epoch,
trust, checkpoint, root fault or identity reset occurs. A heartbeat outage causes
session reconciliation/renewal before later heartbeats.

SIGTERM/SIGINT interrupts the wait and can finish a locally healthy run while
offline, preserving pending requests for the next process. SIGKILL or failed local
health leaves the existing active-run/fault protection in place. `--once` returns
`retry-pending` (exit 2) on transient failure after a clean local finish; it does not
sleep or claim successful reporting. Do not configure an automatic root reset.

The persistent-listener composition and network retry have isolated AWS coverage.
Live testing also exposed the helper-stop race corrected below. Exact package pins,
observed scenarios and remaining limits are recorded in the
installer acceptance evidence (historical, retained privately; not a public acceptance claim).

## Installer stop ordering (0.4.4 dependency alignment)

Host-discover 0.4.4 requires host-install 0.4.3 for the composed beacon's
`KillMode=mixed` stop behavior. This lets in-flight local admission helpers finish
after SIGTERM reaches the beacon; timeout escalation still kills the cgroup. The
0.4.3 network retry runtime, wire protocol, journals, ledgers and consumer templates
are unchanged. Use the installer-generated composition. Do not add automatic reset.

## Explicit session reconciliation (0.4.5)

See [SESSION-RECOVERY.md](SESSION-RECOVERY.md) for the stopped-consumer root operation. A bounded root recovery record blocks ordinary operations until completion; last-recovery.json retains evidence. Ledger and journal schemas remain v1; their protected checkpoint changes without clearing run/fault.
