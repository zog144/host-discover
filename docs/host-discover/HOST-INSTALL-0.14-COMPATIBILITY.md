# host-install 0.14.9 compatibility

**host-discover candidate:** 0.4.14  
**Selected host-install source:** `5c03d935be85622789b18559448e1560066d0a37` (0.14.9, draft PR #11)  
**Selected host-identify source:** `4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b` (0.3.5)  
**Selected box-control source:** `8249715708c6ef8a1fd30a3fb529b4034ffffe25`

This is the exact successor compatibility candidate for the administrator FD
source integration. host-discover 0.4.13 required `host-install==0.14.3`;
the three-owner administrator source contract selected host-install 0.14.9,
which made an otherwise valid environment fail `pip check`.

0.4.14 fixes that mismatch by selecting **exactly** 0.14.9. It does not
introduce a version range and does not silently redefine the already published
0.4.13 source candidate.

The previous accepted compatibility selection was host-install 0.14.3 at
`889f137dc19d1f34fca42fd3dd8df862f8ebae9d`. Comparing that source to the
selected 0.14.9 head shows that the host-discover-imported modules are unchanged:
`state_admission`, `state_contract`, `state_gate`, `state_inspect`,
`state_io` and `state_probe` are not part of the 0.14.3→0.14.9 file delta.
The newer installer adds administrator handoff/receipt and other independent
boot/certificate/profile work without replacing these imported STATE APIs.

## Resident and non-resident reporting

The schema-2 resident/non-resident behavior accepted with 0.14.3 is retained.

For a **resident** installation, the existing behavior is preserved: a retained
foreign boot bundle may identify the supported Amazon Linux provenance path and
allow live AWS metadata observation before the verified generation report is
attached.

For a **non-resident** installation, host-discover does not read or manufacture
resident-only fields. It obtains the authoritative ownership block from
host-install's `host_generation_report()`, reporting externally managed host
OS/boot/root ownership, null Zog HOST slots and no transitional foreign boot
bundle.

The fixed host-discover identity remains UID/GID 970 with supplementary groups
972/973.

## Imported API and native ownership regression

`tests/test_host_install_014_compatibility.py` asserts:

- exact installed host-install version 0.14.9;
- STATE account/path constants;
- retained resident and schema-2 non-resident fixture validation;
- every host-discover-imported function;
- exact `state_io` and `state_inspect` call signatures.

`tests/test_host_install_native_compatibility.py` runs as root on a disposable
GitHub runner and verifies real UID/GID/mode handling, publication/locking and
fail-closed behavior for incorrectly owned existing STATE directories.

No ownership function is mocked in that privileged fixture.

## Dependency closure

`.github/workflows/host-install-014-compatibility.yml` checks out the exact
three companion revisions above on Python 3.12 and 3.13, verifies the
host-install public dual-license/notice inputs, installs the exact components,
and runs **unconditional `python -m pip check`**.

The workflow then runs the full nonprivileged host-discover suite and the
privileged STATE/reporting/recovery fixtures. The candidate is not considered
compatible if dependency closure requires an exception or ignored mismatch.

## Scope

This is source/fixture compatibility only. It does not approve host-install PR
#11 for native installation, enable the administrator FD broker, replace the
station-access accepted companion manifest, or prove root socket/UID/cgroup,
signer, HostIdentity receipt, mounted STATE, systemd or reboot acceptance.

Those remain separate owner/native gates.
