# Live host export for bounded applications

## Why a directory is exported

A selected archive-mirror role needs *fresh non-secret intent* for an authorized consumer, while host-discover retains the private Ed25519 identity and unrelated archive credentials. Its optional `mirror_live_export_directory` is an operator provisioned, ownership-checked directory beneath a narrowly configured host export root.

## Atomic renewal and least privilege

The daemon publishes `mirror-intent.json` and `mirror-candidates.json` atomically inside the same locked role update as its own credential publication. It does not expose private identity state or `archive.json` in this export. An administrator must grant the approved **parent directory** read-only to the exact archive server/scheduler program so inode replacement is observable; a single-file bind may become stale.

## Other program boundaries

The station-access web process must not be given a broad host-directory capability merely to observe archive status. Box-control/root-control independently check a root-owned policy, exact project/application/program and host source identity before allowing a constrained mount. Successful exporter source tests do not prove renewal, DAC and read-only mounts were accepted on a production host.

## Detailed contracts and original evidence

- [HOST-LIVE-EXPORT.md](../HOST-LIVE-EXPORT.md)
- [BEACON-SUPERVISOR.md](../BEACON-SUPERVISOR.md)

The live host, current companion revisions and exact approval gates require separate acceptance. Dated handoffs retain their historical status and do not become production authorization through editorial consolidation.
