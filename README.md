# host-discover

**Documentation:** [Technical manual](docs/host-discover/README.md) · [Source traceability](docs/host-discover/TRACEABILITY.md). The manual organizes current concepts; linked detailed sources preserve exact contracts and historical evidence.

Host-discover is Zog's outbound signed HTTPS beaconer. It reports host identity
and current addresses to the station-access registry, handles explicit key
approval, and optionally reconciles a leased archive-mirror role. It does not
hold AWS account credentials or perform central DNS writes.

This public source package is **0.4.7**. Its canonical repository is
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
No fault, identity or trust reset is automatic. Use the accepted host-install
0.4.3 persistent-listener composition with graceful helper-safe stop; remote commands remain disabled. See the
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
reinterpreted. The producer is host-install 0.4.4; host-discover does not infer
inactive slots or treat the selected slot as booted.

## Public licensing and migration history

Original first-party files in this reviewed repository are licensed under
`BSD-3-Clause OR GPL-3.0-only`: see [LICENSE](LICENSE),
[LICENSES](LICENSES/) and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
This repository has a fresh public Git history; earlier private commits,
handoff reports and operational evidence were not imported.
Local and public CI fixtures do not establish live host enrollment,
native-systemd restart/reboot acceptance or production archive-role readiness.

The public CI checks the repository-only bridge and package contracts, plus
a bounded public host-identify integration suite. Full host-install,
box-control and production acceptance must be revisited when compatible
public source revisions exist.
