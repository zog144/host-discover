# Managed STATE and protected sessions

## Producer and consumer roles

Managed state is not a switch to make any missing host identity valid. Host-install performs root-owned STATE inspection/admission and retains authorization/consumption records; the unprivileged host-discover process rechecks an existing identity under a retained directory descriptor. The older `--managed-state` diagnostic explicitly does not confer full session/admission or remote control.

## Supervised beacon profile

The optional `--managed-beacon` profile requires an explicitly root-prepared supervisor/ledger, a separately enabled station authority, and verified consumed identity. Its session request binds installation/STATE UUID, host identity, registry, boot challenge, checkpoint and epoch. Session renewal and signed heartbeats are bounded operations, never a generic command queue.

## Protected root ledger

The supervisor serializes pending and completed mutations using its root-owned lock and durable ledger; missing/corrupt root-owned records block normal work. A network timeout or lost session response preserves the identical pending request. A reboot does not authorize resetting the checkpoint, installing arbitrary accounts or regenerating a private key.

## Detailed contracts and original evidence

- [MANAGED-STATE.md](../MANAGED-STATE.md)
- [BEACON-SUPERVISOR.md](../BEACON-SUPERVISOR.md)

The live host, current companion revisions and exact approval gates require separate acceptance. Dated handoffs retain their historical status and do not become production authorization through editorial consolidation.
