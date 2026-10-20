# Root-owned certificate authority observation handoff

**Contract:** `zog-host-discover-certificate-authority-observation-v1`  
**Producer:** host-discover root supervisor  
**Input authority:** station-access managed certificate assignment v1  
**Consumer:** local host owner / host-deploy certificate owner  
**Scope:** managed command-center authority only

This contract closes the privilege boundary between the unprivileged
`host-discover` managed beacon and a root-owned certificate consumer.  It does
not create issuer policy, install a Cloudflare token, invoke Certbot, publish a
TLS private key, reload nginx, or authorize a standalone-local administrator.

## Root-owned signing-key pin

Managed certificate assignments are signed by the exact control-registry
Ed25519 key used for the authenticated managed session.  Before that authority
can cross into root-owned certificate policy, the same public key must be
installed independently by the native installer at:

```text
/etc/zog/host-install/certificate-assignment-authority.json
```

The file is root:root mode 0444 under the already protected host-install
configuration ancestry.  Schema:

```json
{
  "schema": 1,
  "kind": "zog-certificate-assignment-authority-pin",
  "registry_id": "primary",
  "authority_public_key": "<base64 raw Ed25519 public key>",
  "authority_key_id": "<sha256 fingerprint>"
}
```

The pin is public information but privileged deployment state.  It must come
from the authenticated station-access/host-install enrollment path, not from
the host-discover UID, a heartbeat response, a browser form, DNS, or the
certificate-assignment response being verified.

The root supervisor rejects an assignment when the managed journal's control
registry key differs from this pin.  A compromised UID 970 therefore cannot
replace its journal with an attacker key and cause that key to become local
certificate authority.

station-access must not advertise certificate-assignment capability v1 until
the native installation has a matching reviewed pin.

## Root checkpoint

The managed beacon first verifies and durably stores the signed assignment in
its existing UID-970 control directory.  It then asks the already installed
root supervisor only to checkpoint certificate authority.  The request carries
no hostname, envelope, signing key, DNS binding, certificate policy, or
credential.

The root supervisor independently:

1. re-observes protected host-install admission and the current supervisor run;
2. requires the exact managed journal digest already checkpointed by root;
3. reopens and validates the anchored UID-970 managed journal;
4. requires the configured control registry, enrolled Host UUID, exact
   installation UUID and no pending managed-session transition;
5. reads the root-owned assignment-key pin above;
6. requires the journal control-registry key to equal that pin;
7. reopens `certificate-assignment.json` as an actual UID-970, mode-0600,
   single-link file and rejects interrupted pending publication;
8. verifies the detached Ed25519 assignment envelope against the root-owned
   pin and exact Host/installation binding; and
9. compares the signed revision/operation against its own independent
   root-owned anti-rollback history.

Only then does it publish:

```text
/state/host-discover-certificate-authority/authority.json
```

The directory is root:root 0700 and the observation is root:root 0600.  An
interrupted replacement leaves a blocking marker; automatic adoption or repair
is not attempted.

The root observation is self-contained.  It carries the pinned public key, key
fingerprint, exact signed envelope, assignment digest and bounded root operation
history.  Its top-level identity fields are:

```json
{
  "schema": "zog-host-discover-certificate-authority-observation-v1",
  "origin": "managed",
  "verified_by": "signed-host-discover",
  "host_id": "<uuid>",
  "installation_id": "<uuid>",
  "state_volume_id": "<uuid>",
  "registry_id": "primary",
  "authority_public_key": "<base64 raw Ed25519 public key>",
  "authority_key_id": "<sha256 fingerprint>",
  "revision": 4,
  "operation_id": "<uuid>",
  "assignment_sha256": "<sha256>",
  "operations": [],
  "envelope": {}
}
```

The root history is intentionally separate from the UID-970 assignment
history.  Lower revisions, same-revision content changes, and reuse of a
previous root-checkpointed operation ID are rejected even if the unprivileged
assignment file was replaced with an older correctly signed receipt.

A network outage or an `unassigned` response never clears the root
observation.  Expiry and revocation remain in the signed envelope and are
enforced by the downstream owner.  A signed higher-revision revocation is
checkpointed exactly like an approval.

## Root inspection

A root-only operator/owner can read the protected record with:

```sh
host-discover-supervisor authority-inspect
```

The command reads only the root-owned checkpoint.  It does not ask UID 970 for
authority and does not synthesize a missing assignment.

## Boundary to host-deploy

This observation is deliberately **not**
`zog-host-deploy-certificate-owner-authority-v1`.  host-discover does not know
or choose the local delivery policy digest.

The host owner must convert a valid managed observation into the host-deploy
owner receipt only after it independently binds:

- the exact local service/consumer identity;
- the exact certificate ID and hostname set;
- the selected issuer/challenge policy;
- the current DNS credential identity and revision when DNS-01 is local; and
- the exact root-owned `policy_sha256`.

The signed assignment's `consumer` is an authority claim, not permission to
select an arbitrary systemd unit.  host-deploy must map it to an approved local
consumer policy and reject a mismatch.

No caller-supplied web JSON or copy of the UID-970 assignment file is a
substitute for the root observation.

## Standalone-local authority

Standalone-local hostname authority remains a separate station-access/host
owner path.  host-discover does not merge, prefer, or manufacture local-admin
authority.  A standalone-local root receipt must come from authenticated local
administrator intent and must conflict with a managed receipt where the host
owner's policy says they cannot coexist.

## Source acceptance

The privileged supervised-beacon regression exercises:

- a real root-owned 0444 signing-key pin;
- a station-signed managed approval;
- automatic root checkpoint after receipt;
- root:root 0600 observation ownership;
- a higher signed revocation; and
- replacement of the UID-970 assignment with the older correctly signed
  approval, which the independent root checkpoint rejects as stale.

The test still uses synthetic station transport and a disposable filesystem.
It is not native systemd/socket, installed-UID, reboot, public DNS, ACME, nginx
or TLS SNI acceptance.  Those remain host-install and host-deploy Work gates.
