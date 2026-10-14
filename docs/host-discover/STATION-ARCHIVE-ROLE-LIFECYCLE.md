# Station/archive automatic role lifecycle

**Date:** 2026-10-13  
**Owner:** host-discover  
**Production controller contract:** box-control `1a3b96579f4a5f8bc8fa18b073fb5e34555b342d`  
**Deployment owner:** host-deploy  
**Status:** source implementation; native systemd/reboot acceptance remains external.

Host-discover remains the sole archive role elector. Box-control executes only
explicit lifecycle requests through its fixed single-application role broker;
the broker does not poll station state, select placement, or supervise the
archive independently.

## Production bridge configuration

For the station/archive production cutover, configure the existing
`mirror_box_control` object in host-discover with the broker socket selected
by host-deploy:

```json
{
  "mirror_box_control": {
    "broker_socket": "/run/zog/archive-role.sock",
    "application": "archive-mirror",
    "required_programs": ["server", "refresh-scheduler"],
    "ca_file": "/etc/host-discover/archive-readiness-ca.pem",
    "timeout_seconds": 10
  }
}
```

`broker_socket` must identify the local systemd-activated
`zog.box_control.role_broker` endpoint. The broker itself is bound by
host-deploy to exactly `archive-mirror`, the trusted project-controller
account, the approved image generation/software view and the non-root
host-discover UID through `SO_PEERCRED`.

The bridge accepts exactly one of `broker_socket` or the historical
`project` selector. Direct project mode is retained for trusted development
and existing controlled deployments; it is **not** the production station
cutover path for the host-discover service account. Never grant host-discover
the project-controller home, privileged root-control socket, root credentials,
or arbitrary command execution merely to make direct mode work.

The application name is fixed to `archive-mirror`. The required program set
defaults to `server` and `refresh-scheduler`. `timeout_seconds` is valid
only with broker mode and remains bounded by the broker client. `ca_file`
belongs to the archive HTTPS readiness probe; it is not broker authentication.

## Lifecycle and durability

A selected role is eligible to launch only while its signed lease is fresh,
the dedicated mirror export can be renewed, the broker confirms the fixed
application exists, preparation reports `ready`, and advisory preflight
reports `ready-to-attempt`.

Before sending `start`, host-discover persists the broker-issued launch
request ID and a launch-attempt marker in `mirror-role.json`. A lost reply
therefore cannot cause another launch identity to be invented. Subsequent
heartbeats inspect the durable request result:

- `satisfied` adopts the returned immutable runtime ID;
- `pending` remains `starting` and is not replayed;
- `unknown` is reconciled through the broker cancellation API using the same
  launch ID;
- terminal `failed`, `abandoned` or `cancelled` evidence does not count as
  serving and permits a later fresh request only after the old identity is
  durably retired.

Withdrawal, lease expiry and role revision replacement first cancel/reconcile
the original launch request. If a runtime is proven, host-discover issues a
**separate termination request identity and persists it before** calling the
termination RPC. Lost termination replies reuse that exact identity. Pending or
uncertain cancellation remains `stopping`; it is never reported as stopped.

A retained runtime observation is interpreted conservatively:

- both required programs active: `running`;
- unavailable, partial, activating/deactivating or malformed evidence:
  `runtime-unavailable`, not serving;
- current inactive/failed program: unexpected `runtime-failed` while selected;
- previous-boot evidence, or a mismatch between a retained invocation ID and
  the currently observed invocation ID: stale runtime evidence, never serving,
  and retired before a fresh launch is attempted.

A scheduler failure while selected is therefore an unexpected runtime failure.
The same failed/inactive state after an explicit withdrawal is valid stop
evidence and is reported as `lease-withdrawn`, not hidden as a successful
serving state.

## Serving readiness

Launch acceptance is never serving readiness. Host-discover reports the role
`ready` only after:

1. broker/controller observation proves both `server` and
   `refresh-scheduler` active for the exact retained runtime; and
2. normal certificate/hostname-validated HTTPS reaches
   `/.well-known/zog/archive-mirror/ready` at the selected endpoint and the
   response exactly binds the host ID and current role revision with
   `serving=true` and `scheduler_running=true`.

The role broker's preflight response is advisory only. A `ready-to-attempt`
preflight result, accepted launch, retained request, old invocation ID or
previous-boot runtime cannot independently establish serving.

## Stable blocked/recovery states

Broker errors are reduced to bounded nonsecret codes. In particular,
`preparation-not-ready`, `application-unavailable`,
`definition-mismatch`, `scope-rejected`, `image-selection-invalid`,
`image-unavailable`, `storage-fault`, `recovery-required`,
`controller-busy`, `controller-blocked` and local
`controller-unavailable` are not serving states. Raw exception messages,
project paths, systemd environment, commands and credentials are never copied
into role status.

The broker's detailed code is consumed locally and translated onto the existing
station-access mirror-status reason vocabulary rather than silently extending a
different owner's wire API. Preparation/cancellation/busy states publish
`operation-pending`; an ambiguous start publishes `start-uncertain`;
definition/scope/preflight contract failures publish `configuration-invalid`;
application absence publishes `application-missing`; controller/image/storage/
recovery unavailability and stale prior-boot runtime evidence publish the
existing `state-unavailable` or `runtime-unavailable` categories. A terminal
launch or live-program failure publishes `runtime-failed`.

Existing-only host enrollment remains unchanged. The broker configuration does
not replace or regenerate the host identity, does not copy enrollment
credentials into archive applications, and does not broaden the dedicated
read-only `mirror_live_export_directory` capability.

## Source verification

Focused host-discover tests:

```sh
python -m pytest -q tests/test_box_bridge.py tests/test_roles.py
```

The repository's GitHub Actions packaging workflow also runs
`tests/test_box_bridge.py` without sibling repositories so broker selection,
scope, sanitization and runtime-observation classification remain continuously
checked. Full `tests/test_roles.py` requires the exact host-identify and
host-install source dependencies from `version-share-handoff.json`.

Production acceptance remains a host-deploy Work responsibility and must use
the host-deploy-reviewed broker socket/project owner, immutable generation,
software view, grants and prepared persistent storage. It must exercise fresh
role placement, withdrawal racing launch, lost replies, controller/broker
restart, offline boot, retained request recovery, role re-selection,
unavailable controller, prior-boot observation, missing/expired mirror export
and a genuine host reboot. The station portal remains independently booted and
must stay available while the archive role is withdrawn.

No source test in this repository authorizes nginx/443 cutover or the final
production migration.
