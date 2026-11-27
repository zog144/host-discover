# Approved Host managed HTTPS — 2026-11-27

Source candidate based on the explicitly selected host-discover 0.4.9 commit
`0f2c6fd5cb33528ed2fe9fd1c855d2f691db6f80`. This is not credential delivery,
certificate assignment, remote-control admission or authorization to modify a live Host.

## Why the disabled transport is not switched on

`managed_transport.Transport.post` is the disabled experimental adapter; its
Runtime includes command inspection and is not a protected production entry
point. The selected tree already contains the real TLS client `beacon.HTTPS`,
the supervised `--managed-beacon` profile, durable pending request and epoch
reconciliation, and the root supervisor. The new explicit CLI
`host-discover --managed-approved-beacon [--once]` reuses that implementation.
It never invokes enrollment and does not use the experimental adapter,
legacy fallback, archive/mirror role execution, certificate assignment retrieval
or remote commands. Existing narrow diagnostic and historical managed/fresh CLI
semantics are unchanged.

## Independent authority expectation

A privileged, reviewed installer/operator must first verify actual approved
station HostIdentity, the installed Host fingerprint, installation UUID,
STATE volume UUID, exact registry ID and canonical HTTPS origin, station
authority UUID and the actual current station managed Ed25519 signer through
an independent authenticated station/operator channel. The signer fingerprint
must **not** be inferred from a session response or from a candidate export.
Keep production signer private material on the station.

Install a single-link root:root mode 0444 regular file
`/etc/zog/host-install/managed-station-binding.json` below root-controlled
non-writable, non-symlink directories. Its strict v1 JSON keys are:

```json
{
  "schema": 1,
  "kind": "zog-managed-station-binding",
  "host_id": "<approved canonical UUID>",
  "fingerprint": "<retained Host public key SHA-256>",
  "installation_id": "<verified installation UUID>",
  "state_volume_id": "<verified STATE UUID>",
  "authority_id": "<configured station authority UUID>",
  "registry_id": "<configured control registry ID>",
  "origin": "https://registry.example.invalid",
  "station_key_id": "<independently authenticated station public key SHA-256>"
}
```

Illustrative placeholders only; none authorize an installation. No secrets.
This expectation is intentionally distinct from the later five-field
certificate-assignment-authority pin whose exporter requires existing live
managed admission. Do not use the latter's candidate export to bootstrap trust.

The root-owned record is validated against inspected bootstrap and consumed
identity, reread before and after network activity, and checked against the
journal's Host UUID and any established signer. A first journal can be seeded
only when the existing root supervisor authorizes its **initial** creation,
using the approved UUID and existing receipt fingerprint. No reinitialization
of an existing empty, mismatched, missing or incomplete journal, no reset of
epoch/checkpoint or station history; such cases require reviewed reconciliation.
There is no network request when the expectation is missing or changed.
On the first managed-session response the station public key must match the
independent expected fingerprint before verifying the signed exact session
claims or committing the session checkpoint. If the station advanced history
but the reply is wrong or uncertain, retain pending state; do not erase it.

## Native Work acceptance, ordered

1. Record existing approved Host UUID/fingerprint, source and installed RECORD
   digests, boot ID, installation/STATE UUID, actual mount, protected consumed
   identity receipt, original key inode and root supervisor/journal state.
   Check station's approved HostIdentity and managed admission history, and
   independently authenticate station signer and authority/registry IDs.
   If the Host is only legacy beaconing or directory-backed STATE, **stop**:
   the managed profile requires the original verified mounted STATE and
   consumed identity. Do not manufacture a receipt, re-enroll, regenerate a key,
   or adopt the old terminated Host.
2. Install the exact reviewed successor with its compatible host-install 0.10.0
   and host-identify 0.3.4 public selections (or separately reviewed closure).
   Verify package bytes. Root owner provisions the independent binding and the
   supported persistent admission/supervisor listener composition from
   host-install beacon-stage, if not already present. Preserve existing
   root journal/ledger; do not call prepare again on operated state.
   Verify the actual sockets, service UID/GID, signer and TLS CA.
3. Confirm station's managed-session endpoint is enabled for the selected
   authority, approved fingerprint/Host and HTTPS origin. Stop competing
   beacon processes; select the explicit approved CLI in the composed service.
   Use `--once` under the intended service account and identical sandbox for a
   controlled proof. Exit 0 with `verified_binding` means a checked signed
   session and accepted heartbeat; blocked or retry-pending is not success.
   This output contains public Host UUID/fingerprint, installation/STATE UUID,
   authority/registry, signer fingerprint, boot ID, epoch/checkpoint and expiry,
   not session token or private material. Compare with actual station DB
   ManagedAdmission and read-only station signer evidence, including freshness.
4. Repeat session renewal at expiry and a clean stop/restart; simulate temporary
   network outage/reconnect with identical retained Host identity and no
   enrollment request. Confirm next epoch and checkpoint at station, unchanged
   Host/installation/STATE/fingerprint and no credential or command effects.
   Retain the matched local/station observation for station-access #1.
   Network failure does not authorize a journal reset; expired unresolved
   responses still require explicit existing recovery procedures.

Source tests use disposable synthetic STATE and a real loopback TLS server
with host-signed requests and fixture station signed session responses. They
are not live station, signer provenance, systemd, or real Host acceptance.
The source candidate changes no production pins or live configuration.
