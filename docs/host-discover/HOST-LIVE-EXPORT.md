# Live mirror intent export for box-control host capabilities

host-discover owns the live role writer; station-access must not receive the
host enrollment keys, private identity tree or unrelated archive credentials.

The optional administrator-set `mirror_live_export_directory` configuration
selects an already provisioned directory below either
`/run/zog-host-export/` or `/var/lib/zog-host-export/`. The directory must
exist with mode 0750 and be owned by the host-discover process; host-identify
checks ownership and every ancestor for unsafe symlinks/writable directories.
The operator chooses a narrow group for the station scheduler only.
The producer atomically writes **only** the non-secret
`mirror-intent.json` and `mirror-candidates.json` with mode 0640 and that
directory's group. It does not publish `archive.json`, private identity
keys, or a shared credential directory.

Export is performed within the same locked role tick as the ordinary
host-discover credential publication and is retried on subsequent ticks.
Renewals and withdrawals replace child files atomically; binding the parent
directory rather than a file inode exposes the new bytes to consumers.
A selected role cannot be acknowledged ready when the export fails. On
withdrawal, runtime stop is still attempted but a failed export prevents
an unqualified safe-stopped acknowledgement.

box-control's root-owned `/etc/zog/host-bindings.json` policy can grant this
exact export **directory** to the `station-access` scheduler program as a
read-only host capability at `/run/zog-host/mirror-live`. The web program
must not receive that grant. The source must never be the general
`/var/lib/host-discover/credentials` directory. Root-control separately
verifies source identity and preserves the host owner.

This is source/test support only. Provisioning a directory, choosing its group,
adding a root-owned binding policy, relaunching services and testing real
mount-namespace/lease behavior must be coordinated through the existing
host-deploy ownership workspace. A socket/control gateway and the production
station state/archive migration remain separate blockers for HTTPS port-443
cutover.
