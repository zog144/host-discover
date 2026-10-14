# Beacon, host identity and inventory

## Transport versus identity

Host-discover transmits periodic signed Host evidence; host-identify owns the key and signing primitives, host-install owns installed STATE/slot facts, and station-access owns approval. A reported account/instance/address is an observed assertion that must be matched independently to cloud inventory before granting DNS or deployment authority.

## Enrollment, heartbeats and selection

The maintained signed beacon profile authenticates an exact Host key/fingerprint and sends bounded reports about identity, address, host generation and selected role. Reconfiguration cannot silently change its enrolled Host UUID, registry authority or selected identity merely because a heartbeat destination changes. Multiple beacon URLs remain explicit configuration and are not proof of acceptance.

## Host generation is verified separately

The owner verifies selected HOST-A/HOST-B slots and, when possible, actual booted slot using the host-install producer. An unknown boot root stays unknown; a transitional foreign boot does not become a native Zog boot because a generation was selected.

## Detailed contracts and original evidence

- [HOST-INSTALL.md](../HOST-INSTALL.md)
- [MANAGED-STATE.md](../MANAGED-STATE.md)

The live host, current companion revisions and exact approval gates require separate acceptance. Dated handoffs retain their historical status and do not become production authorization through editorial consolidation.
