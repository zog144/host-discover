# host-install 0.10.0 compatibility

**host-discover release:** 0.4.9  
**Selected host-install source:** `325b6c95320d04ad14b987f25e07c1361b7e6f04`  
**Selected host-identify source:** `1a5eac0b255c995022db6a3a4c0051efffa748cc`  
**Selected box-control source:** `8249715708c6ef8a1fd30a3fb529b4034ffffe25`

This compatibility revision addresses the public-migration acceptance finding that
host-discover still declared `host-install==0.4.4` while the selected immutable
public host-install component is 0.10.0. The dependency change is not a resolver
workaround: host-discover tests the exact selected companion source before this
revision is acceptable.

## Imported host-install surface

host-discover 0.4.9 directly uses these host-install modules:

- `state_admission`: protected observation, current bindings, live authenticated
  admission and systemd-listener serving;
- `state_contract`: canonical JSON, decoding, field/header validation, fixed
  digest/UUID rules and complete STATE bundle validation;
- `state_inspect`: anchored directory/file checks, live STATE inspection and
  verified host-generation reporting;
- `state_gate`: pure lifecycle decision over authenticated evidence;
- `state_probe`: bounded writable-STATE health probe;
- `state_io`: no-replacement directory creation, durable publication, raw reads
  and durable operation locking.

The exact 0.10.0 source retains those APIs and the call shapes used by
host-discover.

## STATE ownership and paths

The selected 0.10.0 contract still assigns the dedicated host-discover account:

```text
uid=970
gid=970
supplementary groups={972, 973}
```

and retains:

```text
/state
/state/host-discover/identity
/state/host-discover/trust
/state/host-discover/control
```

The retained host-discover synthetic bundle is validated by the actual 0.10.0
`state_contract.validate()`; the tests do not reconstruct a relaxed substitute.

## Exact companion CI

`.github/workflows/host-install-010-compatibility.yml` checks out the exact
three public companion commits above on Python 3.12 and 3.13. It installs those
sources and compiles host-discover. Tests are deliberately separated by
privilege: ordinary source-level tests run as the unprivileged Actions account,
while the supervisor, outage/retry and recovery suites run under sudo because
they invoke the production root-only preparation/reconciliation paths.

In the privileged fixture path the synthetic host-discover STATE directories
are actually chowned to UID/GID 970. Because the synthetic test keeps the root
supervisor and UID-970 beacon in one Python process, it has one narrow creation
shim: newly created `managed.lock` and `managed.pending` inodes are chowned to
970, exactly as they would be by the real service identity. Ownership/mode
verification is not mocked, and the recovery implementation retains its real
`fchown` behavior. Ordinary non-root unit runs use only the pre-existing narrow
metadata-reader adaptation so they can remain source-only.

The same privileged step runs
`tests/test_host_install_native_compatibility.py`. That fixture performs real
numeric ownership/mode operations through host-install's `ensure_directory`,
`metadata`, `lock`, `publish` and `raw` functions. No UID, `chown`,
ownership metadata or permission setter is mocked there. It also proves that a
pre-existing wrongly owned/mode STATE directory is rejected without being
repaired in place.

This is intentionally narrower than live production acceptance. It does not
claim that GitHub Actions reproduces a mounted Zog STATE volume, NSS account
provisioning, SELinux, native systemd socket activation, reboot recovery or a
real enrolled station. Those remain native Work acceptance obligations.

## Packaging/source closure

The component packaging gate no longer checks a hand-maintained subset of Python
modules. It derives the required wheel closure from every tracked
`src/zog/host_discover/**/*.py` file and every packaged systemd file, and checks
the same complete source/package-data closure in the sdist together with all
declared license/notice files.

host-deploy still owns the six-component publisher manifest and must regenerate
its exact file hashes from the accepted immutable component commits. This
host-discover gate makes omission of a new host-discover runtime module or
package-data file a component CI failure rather than relying on a historical
fixed file list.
