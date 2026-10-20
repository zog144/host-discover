# Command-center certificate hostname assignment transport

**Contract:** host-discover certificate assignment v1  
**Owner:** host-discover transport; station-access produces assignments  
**Scope:** managed/command-center authority only  
**Not covered:** standalone local administrator authority, DNS/provider writes,
certify-manage policy installation, issuer launch, certificate publication, nginx
reload or production CA issuance.

This contract implements the host-discover portion of the
`2026-10-14-local-certificate-assignment` handoff. It deliberately keeps
certificate authority separate from the ordinary host heartbeat and from
`zog-certify-manage-v1`.

A heartbeat proves that an enrolled host key sent an observation. It does
**not** grant a hostname, DNS authority or certificate operation.

## Trust and ownership

The host sends every retrieval as its normal RFC 9421 Ed25519 signed request.
The station must apply the same host-key binding and replay-nonce persistence
used by the signed heartbeat.

The assignment itself is a second trust object. station-access signs the
canonical assignment with an Ed25519 command-center assignment key. The
detached signature is retained with the assignment so a later root-controlled
owner can distinguish centrally approved authority from an application-writable
proposal.

For the ordinary configuration-based daemon, the public assignment key is
provisioned explicitly:

```json
{
  "certificate_assignment": {
    "authority_public_key": "<base64 raw Ed25519 public key>"
  }
}
```

The key is public, but the configuration is still operator-owned deployment
state. It is independent from the host's private identity and from TLS CA
validation.

For the supervised managed beacon, the assignment signature key is the exact
control-registry public key already bound into the protected managed session
journal. Before that key may authorize a root-owned certificate consumer,
0.4.10 additionally requires the same public key to be installed independently
in root-owned host-install configuration. The root supervisor rejects a managed
journal key that differs from that pin. Existing managed deployments are not
forced onto the new endpoint.
The authenticated heartbeat may advertise only the capability:

```json
"certificate_assignment": {"version": 1}
```

That advertisement contains no hostname, policy, command or credential. Only
after that opt-in does host-discover call the separate assignment endpoint.
Observation registries cannot advertise or supply this authority.

## Retrieval endpoint

Host-discover sends:

```http
POST /api/hosts/<host-uuid>/certificate-assignment/
Content-Type: application/json
<normal host HTTP Message Signature headers>
```

Request schema:

```json
{
  "schema": "zog-host-certificate-assignment-request-v1",
  "host_id": "01234567-89ab-cdef-0123-456789abcdef",
  "installation_id": null,
  "known_revision": 0,
  "known_operation_id": null,
  "managed_session": null
}
```

The ordinary signed daemon sends `installation_id=null` and
`managed_session=null`. A supervised managed host sends its protected
installation UUID and current managed-session UUID. There is intentionally no
FQDN in the request: an enrolled host can retrieve its first name assignment
without first knowing one.

The request body is bounded and covered by the existing host signature. The
station must authenticate the exact host binding, reject replayed HTTP
signature nonces, and for managed requests validate the supplied current
managed session. Browser login, CSRF state or a web administrator session is
never sufficient authentication for this machine endpoint.

## Response schema

All successful retrievals are HTTP 200 JSON:

```json
{
  "schema": "zog-host-certificate-assignment-response-v1",
  "host_id": "01234567-89ab-cdef-0123-456789abcdef",
  "state": "receipt",
  "revision": 4,
  "envelope": {}
}
```

Allowed states are:

- `unassigned`: revision 0, envelope null, valid only when the host reports
  known revision 0;
- `unchanged`: exact same nonzero known revision, envelope null;
- `receipt`: a signed assignment envelope is supplied.

A 401/403, outage or malformed response does not silently revoke a previously
signed receipt. The retained authority remains usable only until its own
expiry and only by a downstream owner that independently accepts it. Explicit
revocation is a higher-revision signed receipt.

## Signed assignment envelope

Envelope:

```json
{
  "schema": "zog-certificate-assignment-envelope-v1",
  "key_id": "<sha256 of raw Ed25519 public key>",
  "assignment": {},
  "signature": "<base64 64-byte Ed25519 signature>"
}
```

The signature input is the ASCII bytes:

```text
zog-certificate-assignment-v1 NUL
+ canonical JSON of assignment
```

where canonical JSON is UTF-8/ASCII JSON with keys sorted, no insignificant
whitespace and separators `,` and `:`. The NUL is one byte `0x00`.

Assignment:

```json
{
  "schema": "zog-certificate-assignment-v1",
  "authority_origin": "command-center",
  "host_id": "01234567-89ab-cdef-0123-456789abcdef",
  "installation_id": null,
  "operation_id": "11111111-2222-3333-4444-555555555555",
  "revision": 4,
  "status": "approved",
  "approved_at": 1792098000,
  "revoked_at": null,
  "expires_at": 1792184400,
  "certificate_id": "station-https",
  "hostnames": ["station.hosts.example.test"],
  "contact_email": "acme@example.test",
  "acme_directory": "https://acme-v02.api.letsencrypt.org/directory",
  "challenge": "dns-01",
  "dns_mode": "local-cloudflare",
  "dns_zone": "hosts.example.test",
  "credential_id": "cloudflare-station",
  "credential_revision": 3,
  "consumer": "station-access"
}
```

The example UUIDs/timestamps/names are placeholders.

For a supervised managed host, `installation_id` is the exact protected
installation UUID. For the ordinary signed daemon it must be null.

`operation_id` is the idempotent authority-operation UUID. It cannot later be
reused for different assignment contents.

`revision` is per-host monotonic and positive. Every reassignment, credential
revision change, approval change or revocation requires a higher revision.

`status` is exactly `approved` or `revoked`. Revoked receipts require
`revoked_at`; approved receipts require null. `expires_at` always remains
bounded after `approved_at`; host-discover v1 accepts no authority lifetime
greater than 31 days. An expired receipt is retained as provenance but is not
returned by the active-assignment API.

`hostnames` are canonical, lowercase, unique and sorted. Wildcards are
accepted only with DNS-01.

`challenge` is `http-01` or `dns-01`.

For HTTP-01 all DNS-binding fields are null.

For DNS-01, `dns_zone` is required and every assigned hostname must be that
zone or a descendant. `dns_mode` is one of:

- `local-cloudflare`: requires a nonsecret `credential_id` and positive
  `credential_revision`. No token is transported.
- `command-center-broker`: credential ID and revision must both be null.
  This reserves the authority shape for a future restricted DNS challenge
  broker; it does not implement that broker.

`consumer` is the exact local certificate consumer identity, for example
`station-access`. It is not a program selector or arbitrary command.

## Retained state and conflict handling

Ordinary mode stores the latest verified state at:

```text
<identity_directory>/certificate-assignment.json
```

mode 0600, under the same protected host-discover identity directory.

Managed mode stores the same schema as a separate 0600 file in the already
anchored host-discover control directory. It does not change the v1 managed
journal schema. A pending replacement marker left by interrupted publication
blocks automatic adoption until recovery.

The retained record includes a bounded history of up to 128
`operation_id -> assignment SHA-256` bindings. It therefore rejects:

- a lower revision after a higher one was retained;
- the same revision with different content;
- reuse of an old operation ID for a different revision/payload;
- a different Host UUID;
- a different managed installation UUID;
- a receipt signed by another key;
- `authority_origin` other than `command-center`;
- a local Cloudflare hostname outside its authorized zone;
- a command-center broker receipt carrying a local credential binding;
- malformed, oversized or unsafe retained state.

Once the bounded operation history fills, v1 blocks rather than forgetting old
idempotency evidence. A reviewed migration may define a successor state
contract.

A higher central revision may legitimately change an FQDN or credential
revision, but host-discover only transports that fact. It does **not** assert
that the local root owner has migrated its currently installed certificate
policy or provider secret. The downstream owner must reject a conflicting
standalone-local grant or changed credential version until the corresponding
local authorization is explicitly revalidated.

The UID-970 host-discover state is not the root owner's anti-rollback ledger.
0.4.10 therefore adds a root-supervisor checkpoint which independently reopens
the anchored service-owned receipt, verifies it against a separately installed
root-owned assignment-key pin, and persists an independent root history at
`/state/host-discover-certificate-authority/authority.json`.

That root observation is still not issuer policy: the host owner must bind it
to the exact local consumer and policy digest before installing or renewing.
Rolling the UID-970 assignment state back cannot roll the root checkpoint back.
See [CERTIFICATE-AUTHORITY-OWNER-HANDOFF.md](CERTIFICATE-AUTHORITY-OWNER-HANDOFF.md).

## Expiry and revocation behavior

`active_assignment()` returns an assignment only when:

- the retained detached signature still verifies against the configured/pinned
  authority key;
- the exact host/installation binding still matches;
- status is `approved`;
- `approved_at <= now < expires_at`.

Expired, revoked or not-yet-valid receipts remain inspectable but inactive.
Network loss does not extend the expiry. A station outage therefore cannot turn
stale cached data into fresh authorization.

A signed higher-revision revocation immediately makes the assignment inactive.
A later replay of the older approval is rejected by monotonic revision state.

## Boundary to certify-manage and local authority

This receipt is **not** the root-owned `zog-certify-manage-v1` policy.
host-discover never writes `/var/lib/zog-certify-manage/dns/cloudflare.ini`,
never reads a station-access credential vault, never calls Certbot and never
launches `certify-manage issue`, `renew` or `stage`.

box-control/root-control/host-deploy must separately verify the receipt and the
currently approved local-provider/challenge authority before rendering the
existing issuer v1 policy. In particular, central and standalone-local grants
for the same local TLS consumer must not be merged or auto-preferred.

The issuer private key and published nginx certificate remain local to the
installation.

Assignment-authority key rotation is also explicit. v1 pins one Ed25519
authority key; replacing that pin while retained state is signed by the old key
fails closed. A reviewed trust transition must preserve/verifiably migrate the
old receipt and the root owner's monotonic checkpoint rather than silently
discarding them.

## Source verification

With the reviewed public host-identify dependency installed:

```sh
python -m pytest -q tests/test_certificate_assignment.py
```

The focused tests cover initial retrieval without a pre-existing FQDN,
request-signature verification, expiry, explicit revocation, stale rollback,
same-revision conflicts, operation-ID reuse, wrong host/origin/signature,
provider-zone scope, credential revision changes and cached-state behavior
during transport failure.

The full managed dependency suite additionally covers opt-in retrieval through
the protected control registry and anchored managed state. The privileged
supervisor suite covers the 0.4.10 root-owned assignment-key pin, root
checkpoint, signed revocation and rollback rejection.

These source tests perform no DNS provider writes, public ACME issuance or
production TLS cutover.
