# Administrator credential: exact source rights and distributable notices review

**Review scope:** source-only, recorded November 2, 2026. Tracking: [host-discover #4](https://github.com/zog144/host-discover/issues/4). See machine-readable [source ledger](source-provenance-2026-11-02.json), independent [source verifier](../../tools/review_admin_credential_provenance.py) and [wheel-notice collector](../../tools/inventory_admin_credential_wheel_notices.py).

## Review disposition

**PASS — observed exact source ancestry, license/notices presence and matching candidate consumer CI.**
**HOLD — per-revision first-party authorship/permission attestation and full distribution notice clearance.**

Those two conclusions must never be merged into one "accepted" boolean. A source repository carrying a valid-looking license file and a user having GitHub admin permission are useful facts, but neither establishes that the named license grantor legally controls all newly added code and fixtures. None of the reviewed commits is signed. Absence of a signature alone is not evidence of infringement.

The station-access candidate JSON currently records `rights_acceptance=accepted`; that field is **only an earlier source declaration/consumer review**, not the independently authenticated legal clearance requested by #4. The more specific rights status in this evidence ledger is **pending-independent-per-revision-attestation**. If a consumer requires positive legal clearance before source promotion, this ledger's HOLD takes precedence. Do not rewrite the accepted October 22 `public-companion-pins.json`.

## Reviewed immutable candidate revisions

| Component / purpose | SHA | Version | Ancestor |
| --- | --- | --- | --- |
| host-identify canonical HTTPS protocol | `4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b` | 0.3.5 | accepted `1a5eac0b…` |
| host-discover dependency correction PR #2 | `ed63d8df3cb733192c82b60dd95d13389b9922b5` | 0.4.14 | `ebe83775…` |
| host-discover administrator profile PR #3 | `4653cbffcef627dd8945dcb0d14deac5947e97fa` | 0.4.14 | second parent is exact PR #2 SHA |
| host-install PR #11 administrator receipt/handoff | `5c03d935be85622789b18559448e1560066d0a37` | 0.14.9 | `17e3e0e6…` |
| station-access PR #18 disabled receiver | `a7faf74b23478f473cfb7908306bdc2dd5b3cffc` | 0.4.29 | `c2540cc5…` |

Each selected tree has the repository's BSD-3-Clause OR GPL-3.0-only first-party grant, both complete texts and a third-party notice file; the ledger records actual Git blob identities. First-party notice wording expressly does not relicense separately acquired third-party source or prior private snapshots. PR #3's merge-ancestry repair is content-neutral, and its effective diff against PR #2 contains exactly three profile files. No binary or vendor asset appeared in the reviewed candidate-scoped deltas; source-level comparison cannot establish provenance of independently generated/copied text without a rights-holder declaration.

The copyright field identifies **Alex Black (pseudonym)**. GitHub records the `zog144` account as admin for host-discover, host-install and station-access and as the commit actor, but this account's permission does not independently authenticate the copyright holder's identity, control over contributions or authorization to apply the stated dual license. Neither this reviewer nor a CI process can manufacture that authorization.

## What remains for authentic source-rights approval

A rights-holder or independently authorized source steward must file a reviewable, non-secret attestation that binds **each full SHA above** and states:

1. Which parts of each candidate diff are original first-party contributions; which (if any) originated with independent contributors, generated code, copied sources or external artifacts.
2. Their actual authority to license/relicense those contributions as `BSD-3-Clause OR GPL-3.0-only`, with contributor permission/assignment evidence as needed. A private identifying document need **not** be published; a traceable approval record with stable digest and authorization chain is sufficient.
3. Any third-party material introduced with attribution, source URL, exact artifact/hash, license and distribution conditions; explicitly record "none identified" only after review, not as a default assertion.
4. Confirmation that this grant covers only the stated **public exact revision** and preserves the historical private-revision and third-party exclusions.
5. Signer, date, exact object IDs, evidence location, and any limitations. Self-attestation by the unverified repository account alone is not independently authenticated clearance.

This review must remain blocked on the above; absence of an attestation is **not** a finding of infringement.

## Third-party distribution inventory and release limits

The candidate runtime uses five separately maintained source components, with versions defined in the JSON ledger and exact source license digests. For station's third-party Python environment, the tested requirements file is `requirements-security-tested.txt` (Git blob `60ade235e24b8bcba29b16a0fd0cfbc144a1d855`), containing **28** exact version pins. Exact testing also selected `dbus-next==0.2.3` and compatible `dnspython>=2.8,<3`. The dependency notice workflow:

- downloads the **actual selected wheel bytes** from the registry without modifying a production environment;
- rejects missing/unexpected/duplicate wheel names or wrong exact requirements;
- records SHA-256 of each wheel, distribution version, declared license metadata, every discoverable supplied LICENSE/COPYING/NOTICE/COPYRIGHT/AUTHORS/THIRD-PARTY file, their byte hashes and full original text;
- packages `python-wheel-inventory.json` and `PYTHON-WHEEL-NOTICES.txt` as GitHub Actions evidence, **without uploading third-party wheels**.

A wheel without a discoverable legal file or declaration remains explicitly marked for manual follow-up. Supplied notice text does not prove that embedded vendored code, optional dependency extras, source offers or entire distribution terms were fully reviewed. The Python environment is only the *tested candidate environment*, not necessarily release-build's final resolved wheel set. Before distributing, release-build must reconcile the actual selected distribution names and wheel hashes, source vs binary licensing, all obligations, aggregate Zog components and final artifact packaging.

Station-access's frontend separately retains [exact npm tarball license evidence](https://github.com/zog144/station-access/blob/a7faf74b23478f473cfb7908306bdc2dd5b3cffc/frontend/license-evidence.json) for React, React DOM, scheduler, React Router and Vite helpers. Actual release frontend output must retain its generated hashed LICENSES asset, linked HTML notice and `frontend-build.json`, with no different package/output silently treated as reviewed. Developer npm dependencies are not automatically distributed browser code; other assets such as separately deployed noVNC remain outside that coverage.

There is **no** claim of notice completeness for rootfs, kernel, VNC, systemd, Certbot, nginx, firmware or other native binaries; archive-mirror/image-build/release-build own their artifact-specific source and notice evidence. Final release distribution also needs any license-required source offer or corresponding-source handling.

## Consumer evidence, independent from rights

- [host-discover Python 3.12/3.13 installer compatibility](https://github.com/zog144/host-discover/actions/runs/41307288497): SUCCESS, includes clean pip check and STATE fixture suites.
- [station-access exact three-owner administrator profile](https://github.com/zog144/station-access/actions/runs/41312415374): SUCCESS, exact signed authorization and negative sealed-FD/receipt source tests.
- [canonical HTTPS v1 interoperability](https://github.com/zog144/station-access/actions/runs/41312415375): SUCCESS, Python 3.12/3.13.
- [station-access full Public Source Acceptance](https://github.com/zog144/station-access/actions/runs/41312415358): SUCCESS (wheel/namespace, frontend and Django integration).
- [host-install source and receipt CI](https://github.com/zog144/host-install/actions/runs/41307164882): SUCCESS.

These tests show compatibility for those **fixed candidates**, not ownership of code, independently authorized installation, deployed-byte attestation, root-FD chain, Host-signed completion, certificate or password delivery.

## Release/activation decision

**NO-GO** for source-rights promotion, any new production companion pin, artifact publication, native receiver installation, credential transfer and Host-signed receipt based on this evidence alone. The separate source review can be completed once the exact-SHA rights-holder permission record is supplied and the final distributable notice inventory is accepted by the responsible release owner. Do not erase historical evidence or make operational changes as part of this task.
