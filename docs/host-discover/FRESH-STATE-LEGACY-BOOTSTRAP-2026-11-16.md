# Fresh legacy-format Host identity under directory-backed /state

**2026-11-16 · host-discover Regular · source-only candidate**

The obsolete blanket `/state` restriction is removed from `daemon.validate_configuration`. It did **not** test whether `/state` was mounted. The retained identity migration selection in PR #8 (`identity_mode=existing-legacy-migration`, exact path, Host UUID and protected FDs) is unchanged.

## Fresh enrollment

The supported fresh selection uses the **existing** `legacy-bootstrap` mode (or its existing default), with:

- `identity_directory=/state/host-discover/identity`
- `server=https://<new-registry-origin>` (existing HTTPS-origin validation)
- **no** `host_id` from an old Host and **no** existing identity state or saved `binding.json`

Unlike the old host-identify legacy loader, which intentionally rejects `/state`, the host-discover-local `fresh_state_identity.load_or_create` handles this path. This is **not** the retained migration loader and does not consume a migration receipt. It is not a new registrar or signing service.

For initial creation, the identity directory must be fully **empty**, an actual directory of mode 0700 owned by the service user. Every ancestor must be a safely owned non-symlink directory (see host-identify `initialization.directory_fd`). The new key is generated only after exclusive creation of `key.lock`. Its PEM and the local `fresh-state-bootstrap.json` provenance marker are created with exclusive file creation and durable directory fsync. If interrupted, partial state **stops bootstrap** rather than generating a replacement.

On ordinary restart, the existing key is reusable **only** with this explicitly created marker, the same registry origin, matching Ed25519 public fingerprint, secure single-link mode-0600 regular files and an optional saved `binding.json` matching that fingerprint and containing a canonical Host UUID. An unmarked old key, old binding, incomplete publication, extra files, substituted key, symlink, hardlink, incorrect owner or unsafe ancestor is never adopted. This distinguishes same-bootstrap restart from silent reuse of an identity enrolled with a previous registry. The marker is locally owned state, **not** independent rights or Host-install authority evidence.

New identity has no Host binding. Its normal signed HTTPS beacon requests `/api/hosts/enrollment/` from the explicitly configured new registry with an empty claimed Host ID. A pending response does not publish a binding. A later normal approval can save a newly assigned Host ID. No previous enrollment or registry authority is inherited.

## Installer/setup requirement

**Host-discover intentionally does not create /state or its account-owned identity parent.** A trusted installer or local explicit setup must:

1. Make `/state` an ordinary root-owned directory if not present (no mount required). On an ordinary filesystem it need not be a separate volume.
2. Prepare `/state/host-discover/identity` as a genuinely **empty** host-discover-owned mode-0700 directory. Prepare its safely owned parent(s) and the separate legacy credential directory with existing ownership/mode requirements.
3. Select `legacy-bootstrap` and the *new* registry origin in the existing configuration; do **not** copy the former `identity.pem`, `binding.json`, key.lock, marker or Host UUID. Retain ordinary service credential, CA trust and destination validation; do not import any old primary-registry destination list.
4. Ensure systemd can write the identity directory with appropriate `ReadWritePaths` and appropriate service user/group, including any configured sandbox restrictions. The setup operation must not modify active production identities, re-enroll an old Host or bypass existing ownership checks.

The source-only CI uses disposable paths under `/state` on a GitHub runner and exercises both missing-root provisioning and an already-created root, unsafe modes, replacement attempts, restart and a synthetic new-registry enrollment request. Native installer/setup adaptation and actual registry enrollment remain Work-owned.

This patch does not change `host-identify`, `host-install`, production companion pins, active Host accounts or service state.
