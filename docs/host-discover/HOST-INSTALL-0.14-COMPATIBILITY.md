# host-install 0.14.3 compatibility

**host-discover release:** 0.4.11  
**Selected host-install source:** `889f137dc19d1f34fca42fd3dd8df862f8ebae9d`  
**Selected host-identify source:** `1a5eac0b255c995022db6a3a4c0051efffa748cc`  
**Selected box-control source:** `8249715708c6ef8a1fd30a3fb529b4034ffffe25`

This successor selection is required for the host-install schema-2
resident/non-resident ownership contract. It also resolves the component
metadata discrepancy observed by native Work: host-discover no longer declares
host-install 0.10.0 while being composed with host-install 0.14.3.

## Resident and non-resident reporting

host-discover no longer reads
`installer_recorded.foreign_boot_bundle` before determining installation
ownership mode.

For a **resident** installation, the existing behavior is preserved: a retained
foreign boot bundle may identify the supported Amazon Linux provenance path and
allow live AWS metadata observation before the verified generation report is
attached.

For a **non-resident** installation, host-discover does not read or manufacture
resident-only fields. It obtains the authoritative ownership block from
host-install's `host_generation_report()`, which reports:

- schema 2 / `verified-host-install-state-v2`;
- exact installation ID, record ID/schema and operation;
- `installation_mode=non-resident`;
- externally managed host OS / boot / root filesystem;
- no selected or booted Zog HOST slot;
- null HOST-A/HOST-B entries; and
- no transitional foreign boot bundle.

The non-resident path does not infer AWS/cloud identity merely because the host
happens to run on EC2. Cloud/provider observation is a separate source of
authority and requires an explicit supported binding rather than resident boot
provenance.

## Default-report enrollment regression

The privileged supervised-beacon suite converts the retained valid resident
fixture into a fully valid host-install schema-2 non-resident bundle and calls
the production `Beacon.tick()` **without injecting a report**.

The test intercepts the actual HTTPS transport boundary after host-discover has
constructed and Ed25519-signed the enrollment request. It verifies that request
with the real host identity key and checks the enclosed report. It also makes
the resident AWS metadata helper fail if called, proving the non-resident branch
cannot be hidden by a prebuilt report or resident provenance.

A pending enrollment response is returned. The test does not approve a Host or
manufacture a station identity.

## Imported host-install surface

host-discover 0.4.11 uses the selected 0.14.3 APIs for protected admission,
STATE validation, fixed account/path ownership, installation ownership mode,
live generation reporting, health probing and durable root/state I/O. The exact
compatibility test asserts these functions and call shapes.

The fixed host-discover identity remains UID/GID 970 with supplementary groups
972/973.

## Exact companion CI

`.github/workflows/host-install-014-compatibility.yml` checks out the exact
three public companion commits above on Python 3.12 and 3.13. Ordinary source
tests run unprivileged; root-only supervisor, reporting, retry/recovery and
native ownership fixtures run under sudo.

This CI is source/fixture acceptance. It does not replace the retained
installation's native systemd, mounted STATE, NSS, enrollment or reboot
acceptance. Work must continue on the same retained installation using the
supported explicit supervisor CAS reset only after host-install reviews this
successor pin.

Station approval/export remains downstream of an actual pending enrollment
request and independent fingerprint verification.
