# Existing host-registry beacon after retained legacy STATE migration

**2026-11-08 · host-discover issue #7 · source-only candidate, native HOLD**

This compatibility branch descends from host-discover administrator profile PR #3 `4653cbffcef627dd8945dcb0d14deac5947e97fa`, including the exact 0.4.14 dependency correction in PR #2. It consumes the companion `zog.host_identify.retained_legacy.load_retained_legacy_fd` (host-identify 0.3.5 successor) and preserves the legacy `--configuration` beacon rather than converting the Host to the managed-beacon service.

## Opt-in consumption

The existing legacy JSON remains unchanged **except** the approved host-install migration's narrow `identity_directory` rewrite to `/state/host-discover/identity`; no new JSON field or enrollment record is required. Host-install's future protected systemd launcher must independently provide the previous public fingerprint and two retained open descriptors, then select:

```text
host-discover --configuration /etc/host-discover/configuration.json
  --existing-legacy-migration
  --retained-identity-fd FD_IDENTITY
  --migration-completion-fd FD_ROOT_COMPLETION
  --retained-fingerprint PREVIOUS_ENROLLED_PUBLIC_FINGERPRINT
```

The line breaks above are illustrative command layout, not a literal shell snippet. FD numbers are **already-open** native-provided inherited descriptors, not files or paths parsed from JSON, and must be distinct. Do not pass secret bytes on arguments or in environment variables. The fingerprint is public but must be independently selected from the reviewed existing Host binding; never trust a registry response to replace it.

The exact completion contract and negative checks are in [host-identify retained legacy identity contract](https://github.com/zog144/host-identify/blob/regular/retained-legacy-state-identity-035-20261108/docs/host-identify/RETAINED-LEGACY-STATE-IDENTITY-2026-11-08.md). It requires a durably committed, root-owned-mode 0600 receipt delivered by FD from host-install, with full migration/plan digest, original key/lock/binding/directory inode identities and original Host UUID/fingerprint/control registry; the identity descriptor is checked against the canonical /state path by symlink-safe walk. A managed initialization receipt **cannot** be used to substitute for this legacy-key transaction.

The source daemon internally selects `identity_mode=existing-legacy-migration` only when the explicit CLI option is present. Legacy `existing-only` and bootstrap behavior remain unchanged for non-STATE paths; neither may read /state. Mixed managed and migration options are rejected.

## Preserved behavior and limits

The existing signed HTTPS heartbeat, Host UUID, control registry endpoint, credential directory, archive/session role integration, trust settings, archive issuer/audience and previously enrolled binding remain as before. The verified descriptor-based binding is used directly; a path reread cannot demote the Host to a new enrollment request. The loader does not call the registry. Registry unavailability returns a normal transport failure and does not erase the key or binding. Ordinary application credential expiry/revocation policy remains unchanged.

If an existing destinations list is selected, the **existing primary registry** is read-only validated, with no new `primary-origin.json`, per-registry identity or CA publication. Disabled secondary destinations remain disabled and are not re-enrolled. An **enabled secondary** requires separately reviewed retained secondary identity completion and is explicitly held; no primary key is reused. Existing pre-migration primary marker/secondary identity files are outside host-install PR #36's closed identity inventory and require native preflight reconciliation rather than deletion or silent adoption.

Required native host-install follow-up:
- Preserve the original pre-rename inode pairs and file bytes, verify actual completed migration journal and root-owned completion publication (schema `zog-retained-legacy-state-identity-completion-v1`) after durable per-step migration and rollback reconciliation.
- Implement protected FD handoff from an authenticated local privileged owner to the unprivileged host-discover service, retaining the verified directory FD and root-owned read-only completion FD across ordinary service restart. Check owner/process credentials, selected migration ID and selected installation/STATE roots independently; source code alone does not attest the FD issuer.
- Update the narrow service drop-in/launcher so it **explicitly** supplies the two inherited FDs and previous public fingerprint; simply modifying `ReadWritePaths` and the JSON identity path does **not** activate this mode. Preserve original active/enabled status and existing credential/endpoint/destination paths.
- Prove normal beacon and role behavior, outage/recovery, native UID/GID 970:970, reboot persistence, independent root postcondition checks and same-operation rollback on the actual disposable/native acceptance setup before touching the retained host.

No new signer, registrar, remote enrollment or authorization from Command Center is introduced for this local legacy move. **No production pins were changed and no actual Host, key, accounts, service, credential, or STATE directory was modified by this source work.**
