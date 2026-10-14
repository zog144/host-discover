# Host integration and verification

## Exact dependency chain

Host-install verifies the persistent STATE mount and records installation identity; host-identify validates/preserves private host material; host-discover consumes those records and sends authenticated reports; station-access decides whether to approve the fingerprint. Installation recipes use exact compatible companion revisions and run under the reviewed service account.

## Test tiers and evidence

Synthetic tests cover strict records, host UUID binding, signature construction, invalid state files, conflict rejection, managed-session mismatch and no-live-admission behavior. The dated host-install validation report records local tests only. A complete live acceptance needs actual mount/admission services, station authority, TLS, reboot recovery, export leases and independent observer checks.

## Separate runtime boundaries

The graphical Workspace network namespace and archive-mirror application mount rights are not synonymous with host-discover's daemon credentials. Root-control-owned host capabilities are narrowly granted and station-access browser access is not a host identity key.

## Detailed contracts and original evidence

- [HOST-INSTALL.md](../HOST-INSTALL.md)
- [VALIDATION-HOST-INSTALL.md](../VALIDATION-HOST-INSTALL.md)
- [HOST-LIVE-EXPORT.md](../HOST-LIVE-EXPORT.md)
- [BEACON-SUPERVISOR.md](../BEACON-SUPERVISOR.md)

The live host, current companion revisions and exact approval gates require separate acceptance. Dated handoffs retain their historical status and do not become production authorization through editorial consolidation.
