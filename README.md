# host-discover

**Documentation:** [Technical manual](docs/host-discover/README.md) · [Source traceability](docs/host-discover/TRACEABILITY.md). The manual organizes current concepts; linked detailed sources preserve exact contracts and historical evidence.

Host-discover is Zog's outbound signed HTTPS beaconer. It reports host identity
and current addresses to the station-access registry, handles explicit key
approval, and optionally reconciles a leased archive-mirror role. It does not
hold AWS account credentials or perform central DNS writes.

This public source package is **0.4.12**. Its canonical repository is
[zog144/host-discover](https://github.com/zog144/host-discover). Consumers
should pin an exact reviewed *public* commit; historical private Git commits
have separate identities. host-deploy assembles its payload from an approved
source selection.

## Install and configure

Linux and Python 3.12+ are required. From this directory:

```sh
# Install host-identify and host-install from independently reviewed
# component source revisions or an approved aggregate Zog environment.
# Local source validation before all companions are publicly available:
python3.12 -m pip install --no-deps .
host-discover --help
```

Adapt [the configuration example](examples/configuration.json)
and [systemd unit](deployment/host-discover.service). Replace
the HTTPS origin and all host-specific paths. Configuration requires absolute
`identity_directory` and `credential_directory` paths and a `server` HTTPS origin.
Use `provider: "generic"` or `"aws"`; AWS configuration additionally binds the
exact account ID, region and instance ID checked against IMDSv2.

Run as a dedicated non-root service account with the required protected state
directories and group access. The identity directory is private to that host;
scoped consumer credentials may be shared only with approved local consumers.
Custom CA trust is optional through `ca_file`; TLS verification stays enabled.

```sh
host-discover --configuration /etc/host-discover/configuration.json --fingerprint
host-discover --configuration /etc/host-discover/configuration.json --once
host-discover --configuration /etc/host-discover/configuration.json
```

`--fingerprint` loads/creates the local key and prints its public fingerprint.
`--once` performs one reporting/reconciliation cycle; inspect reported state and
errors, since command exit alone does not prove approval. Normal operation reloads
configuration and waits 60 seconds after each attempt before the next cycle.

## Enrollment and identity

A new Ed25519 key requests pending enrollment. Compare its fingerprint through a
trusted channel and explicitly approve the exact key in station-access. An AWS
match or migration UUID is a matching hint, never authorization. The daemon stores
its approved binding and rejects an approval or saved binding that contradicts
its configured migration target.

Keep the same private identity across ordinary reinstalls/restarts. Do not clone
it into another host or a reusable image. Migration from an older bearer reporter
requires the staged procedure in the separately maintained station-access signed-deployment procedure
or current host-deploy; bearer-token configuration is rejected by this daemon.

Optional `station_login_file` exports a protected local station-admin credential
only on a bound, signed heartbeat. It is never sent with pending enrollment.
Registry approval alone does not create that export or recover a password from
a Django password hash.

## Archive roles and state

`daemon.py` handles reporting, `roles.py` persists role/lease transitions, and
`box_bridge.py` calls a compatible box-control API. Durable role request identities
are recorded before launch and retained across uncertain responses. Withdrawal or
expiry requests an exact-runtime stop while archive data remains retained.
A missing bridge, missing lifecycle capability or unavailable application reports
blocked rather than starting an improvised process. Production station/archive
placement uses the bounded local role broker rather than granting the beaconer
access to the controller project or privileged root-control socket. See the
[automatic role lifecycle contract](docs/host-discover/STATION-ARCHIVE-ROLE-LIFECYCLE.md).

The provider needs both server and scheduler members plus a separate HTTPS
readiness check. This package does not supply the archive-mirror application or
a usable rootfs. See the station-access mirror startup contract
and the station-access archive adapter integration notes. Those integration
reports identify specific dependency revisions; newer standalone controller
features require a compatible tested deployment before use.

Keep key/binding/role records, scoped grants, login exports and credentials out
of source control. Configuration changes must preserve immutable host identity;
never clear state merely to resolve a binding conflict.

## Certificate hostname assignments and root checkpoint (0.4.10)

An enrolled command-center host can optionally retrieve a separately signed,
versioned certificate/FQDN authority receipt from station-access without knowing
an FQDN in advance. The retrieval is a distinct signed POST endpoint, not a
heartbeat command. host-discover verifies a separately pinned assignment key,
Host UUID, optional managed installation UUID, monotonic revision, expiry,
revocation, DNS-zone scope and idempotent operation identity before retaining
the receipt.

The retained UID-970 receipt is **not** a `certify-manage` authorization
policy and contains no Cloudflare token. In 0.4.10 the managed beacon asks the
existing root supervisor to independently reopen that receipt, require a
separately installed root-owned command-center signing-key pin, reverify the
detached envelope and exact Host/installation binding, and persist its own
anti-rollback observation at
`/state/host-discover-certificate-authority/authority.json` (root:root 0600).

The root observation still does not choose a local service or policy digest.
host-deploy must bind it to the exact approved local consumer and
`policy_sha256` before creating its owner authority receipt. Standalone-local
administrator authority remains a separate station-access/host-owner path.

See the
[certificate assignment transport contract](docs/host-discover/CERTIFICATE-ASSIGNMENT.md)
and the
[root-owned authority handoff](docs/host-discover/CERTIFICATE-AUTHORITY-OWNER-HANDOFF.md).

## host-install 0.14.3 compatibility and non-resident reporting (0.4.11)

The selected public host-install source is now
`889f137dc19d1f34fca42fd3dd8df862f8ebae9d` (version 0.14.3).
This is the first host-discover compatibility selection that explicitly covers
host-install schema-2 resident/non-resident ownership.

The default managed-beacon report path now asks host-install for the installation
mode before consulting resident-only foreign boot provenance. Resident behavior
is preserved. A non-resident installation reports host-install's verified
externally-managed ownership block and does not invent Zog HOST slots, root
generations, transitional foreign boot metadata, or AWS identity merely because
the machine is running on EC2.

CI exercises the real `Beacon.tick()` default-report path on a valid schema-2
non-resident bundle through an Ed25519-signed pending enrollment request; an
already-built report cannot hide this branch.

The fixed host-discover STATE identity remains UID/GID 970 with supplementary
groups 972/973. Native mounted-STATE, NSS, SELinux, systemd, CAS retry and
enrollment acceptance remain separate Work gates. See
[host-install 0.14.3 compatibility](docs/host-discover/HOST-INSTALL-0.14-COMPATIBILITY.md).

## Unified HTTPS credential delivery boundary (0.4.12)

host-discover now selects host-identify 0.3.5's shared credential-delivery v1
protocol, but remains a non-secret integration owner. It can derive exact
enrolled Host/HostIdentity/installation/STATE/control-registry binding evidence
for a future protected receiver; it does not receive credential bytes.

Managed heartbeat responses that attempt to advertise `credential_delivery`
are rejected. Enrollment and the existing inspect-only managed session do not
authorize provider tokens, administrator passwords or other durable secrets.
The protected HTTPS receiver belongs to host-install/root ownership and must
independently verify Credential Authority authorization and local destination
policy.

See [credential-delivery boundary](docs/host-discover/CREDENTIAL-DELIVERY-BOUNDARY.md).

## Tests

With the shared library and its dependencies installed, from this directory:

```sh
python -m pip install pytest
python -m pytest -q tests
```

Tests use local identities and mocked reporting/controller behavior. They do not
approve a real host, modify DNS or establish live archive-provider readiness.

## Destination lists (0.3.3)

Optional `--destinations /absolute/beacon-destinations.json` accepts the owner-only file exported from station-access Administration → Deployments. Primary identity is preserved; additional registries have separate keys and observation-only authority. Use `--fingerprint` with the same arguments for trusted-channel comparison at every destination. See the station-access registry and deployment guidance.

## host-install integration foundation

See [HOST-INSTALL.md](docs/host-discover/HOST-INSTALL.md) for explicit identity initialization,
offline contract verification, compatibility and remaining live-admission work.
This pass does not enable a new Zog-host daemon or remote control channel.

Current managed integration: [narrow STATE diagnostic and experimental transport](docs/host-discover/MANAGED-STATE.md). Production managed transport remains disabled.

## Explicit managed beacon profile (0.4.1)

`--managed-beacon` adds supervised enrollment/session/heartbeats after explicit root
provisioning. The existing `--managed-state` diagnostic remains available. See
[protected supervisor and setup contract](docs/host-discover/BEACON-SUPERVISOR.md). Remote
commands, archive roles and live deployment are outside this profile.

## Managed beacon outage recovery (0.4.3)

The managed beacon retries classified temporary network failures with jittered
exponential backoff capped at 60 seconds. Local admission remains checked during
waits. Pending session requests survive uncertain responses and clean offline
shutdown; each HTTP attempt has a fresh signature nonce. TLS, authentication,
protocol, storage and checkpoint failures still block and require investigation.
No fault, identity or trust reset is automatic. The outage behavior was originally accepted with host-install 0.4.3. The current
0.4.12 source-compatibility gate pins host-install 0.14.3; graceful helper-safe
stop remains required and remote commands remain disabled. See the
[supervisor contract](docs/host-discover/BEACON-SUPERVISOR.md) for precise behavior and limits.

Explicit expired-session recovery (0.4.5): see [operator procedure and contract](docs/host-discover/SESSION-RECOVERY.md). Recovery preserves faults; root reset remains separate.


## Managed host generation provenance (0.4.6)

The managed beacon now attaches `host_generation` only when it is collecting a
live report from host-install's verified STATE context. The block is covered by the
same signed heartbeat as the rest of the report; it is not a separate unsigned feed. The block includes the
installation identity/record, selected slot, actual booted slot when proved by the
live root PARTUUID, HOST-A/HOST-B generation identities, and any recorded
transitional foreign boot-bundle identity.

Legacy collection and caller-injected fixture reports are not upgraded or
reinterpreted. The selected current producer is host-install 0.14.3 at
`889f137dc19d1f34fca42fd3dd8df862f8ebae9d`. Resident reports retain the
existing slot/provenance semantics. Schema-2 non-resident reports instead carry
the explicit externally-managed host ownership block with null Zog slots and no
transitional foreign boot bundle.

## Public licensing and migration history

Original first-party files in this reviewed repository are licensed under
`BSD-3-Clause OR GPL-3.0-only`: see [LICENSE](LICENSE),
[LICENSES](LICENSES/) and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
This repository has a fresh public Git history; earlier private commits,
handoff reports and operational evidence were not imported.
Local and public CI fixtures do not establish live host enrollment,
native-systemd restart/reboot acceptance or production archive-role readiness.

The public CI checks complete package closure, the reviewed host-identify
integration, and an exact host-install 0.14.3 / box-control companion set.
Production mounted-STATE, native systemd, reboot and deployment acceptance remain
separate Work-owned gates.
