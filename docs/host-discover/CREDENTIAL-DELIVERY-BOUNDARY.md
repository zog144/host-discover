# Unified HTTPS credential-delivery boundary

**Shared protocol:** `zog.host_identify.credential_delivery` v1  
**Selected host-identify source:** `4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b`  
**host-discover role:** enrolled binding evidence only; no secret reception  
**Status:** source-only; no network activation or live credential transfer

host-discover participates in the unified Option-B HTTPS credential-delivery
architecture only by preserving exact enrolled identity/binding evidence. It
does not turn its existing beacon or managed inspect session into a secret
transport.

The shared contract is
[host-identify CREDENTIAL-DELIVERY.md](https://github.com/zog144/host-identify/blob/4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b/docs/host-identify/CREDENTIAL-DELIVERY.md).

## Exact managed binding

`zog.host_discover.credential_delivery.managed_binding(...)` returns only:

- approved enrolled Host UUID;
- HostIdentity fingerprint;
- installation UUID;
- STATE volume UUID;
- exact control registry ID;
- explicitly supplied consumer;
- explicitly supplied credential purpose; and
- credential ID.

The helper succeeds only when the named registry is configured as the control
registry, its origin matches the protected configuration, enrollment has a Host
UUID and station public key, and no managed-session key transition is pending.

The result is non-secret and is only input to later protected authorization.
It does not prove operator approval, Credential Authority authorization,
destination admission or installation success.

Observation registries cannot produce this binding.

## Beacon/session boundary

Managed heartbeat responses containing a `credential_delivery` capability are
explicitly rejected with `credential-delivery-channel-denied`.

This is intentional even for an enrolled Host with a valid current managed
session. The managed v1 JWT remains `operations=["inspect"]`; it is not a
generic machine-control or secret channel.

Credential bytes, signed delivery envelopes and installation receipts must not
appear in:

- enrollment requests/responses;
- beacon reports or heartbeat responses;
- `managed.json` or its replay journal;
- certificate-assignment state;
- archive-role state;
- logs or ordinary host-discover configuration/state.

The existing certificate-assignment capability is not precedent for secret
delivery: it transports public authority metadata and is independently
root-checkpointed.

## Protected receiver ownership

The future HTTPS secret receiver belongs to host-install/root-controlled
installation ownership, not the UID-970 host-discover service.

That receiver must independently verify:

1. the exact Host/installation/STATE/control-registry binding;
2. a separately pinned Credential Authority key and signed authorization;
3. the approved consumer/purpose/credential ID and revision;
4. a fresh HostIdentity-signed request ID;
5. durable request/HTTP-nonce anti-replay state before receiving bytes;
6. protected destination ownership/mode before installation; and
7. durable installation before returning a secret-free HostIdentity-signed
   receipt.

host-discover must not be granted read access to root-owned provider tokens,
administrator passwords or other durable secrets merely to reuse its existing
HTTPS client.

## Interruption and rotation

The shared host-identify state machine distinguishes `pending`, `delivered`,
`installed`, `cancelled` and `cancelled-after-delivery`.

A delivery with no installation receipt is uncertain. No second request is
admitted until the first is reconciled. Cancellation after delivery forces a
new credential revision; the exposed bytes are never silently redelivered as
the same revision.

These rules belong to the protected receiver and Credential Authority durable
ledgers, not the host-discover heartbeat journal.

## Purpose profiles

The common transport does not make a purpose automatically available.

Current source boundaries:

- certificate DNS provider credentials may later use a reviewed purpose such as
  `issuer-cloudflare-dns01`, with host-install/certify-manage ownership;
- administrator credential provisioning now has a source-only station-access
  profile using purpose `station-administrator-password`, consumer
  `station-access`, credential ID `station-admin`. host-discover exposes
  `administrator_binding(...)` only as exact non-secret destination evidence.
  The station-access profile reconciles FIRST-LOGIN, `station_login_file`,
  password changes, session revocation and recoverable-secret policy; remote
  delivery remains disabled;
- archive-mirror currently has no approved durable HTTPS credential purpose;
  its existing short-lived scoped JWT is separate.

## Source verification

`tests/test_credential_delivery_boundary.py` verifies exact non-secret binding,
observation-registry rejection, pending trust-transition rejection and malformed
purpose rejection.

`tests/test_managed_admission.py` verifies that an authenticated control
registry cannot enable credential delivery through a managed heartbeat.

The public host-identify integration workflow pins the exact shared protocol
revision above. No test in this source pass sends a real credential, opens a
listener, changes port 443, writes a provider secret or enables remote
provisioning.

## Handoff

**station-access Regular:** implement the Credential Authority/server state only
after each purpose profile has explicit operator-approval semantics. Persist
HTTP nonces, authorization revisions, request state and delivery state before
returning secret bytes.

**host-install Regular:** own the root HTTPS receiver, authority pin, protected
temporary handling, destination policy, installation/removal, restart recovery
and secret-free receipt/cancellation messages.

**host-discover:** remains non-secret. Future changes must not add a
secret-returning method to the managed beacon or widen the inspect-only session
operations.


## Administrator profile reconciliation

The existing `station_login_file` mechanism remains a legacy **push** path:
an operator privately exports a still-current `station-admin` plaintext into a
0600 host-discover file, and an already bound Host may include it in its signed
heartbeat. It is not a source for the new receiving profile and it does not
grant the Host permission to fetch an administrator password.

The source-only administrator receiving profile instead fixes the common
binding to:

```text
consumer = station-access
purpose = station-administrator-password
credential_id = station-admin
```

`administrator_binding(saved, bootstrap, registry_id)` derives only that
non-secret binding from a fully enrolled control registry. It does not carry a
password, Django hash, operator approval, receiver grant, credential revision,
or installation result.

station-access separately binds its proposal to the exact selected
`station-admin` database account and current opaque keyed account revision.
Password changes therefore invalidate stale proposals without making old
FIRST-LOGIN/export plaintext disappear or become current.

The future root receiver must combine this destination evidence with the
station-access operator-approved common-protocol authorization. Neither half is
sufficient by itself.
