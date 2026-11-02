# Administrator credential — exact-revision source provenance and notice ledger

**2026-11-02 · source-only review · [host-discover #4](https://github.com/zog144/host-discover/issues/4)**

This document accompanies `verification/admin-credential-source-provenance-2026-11-02.json`.
The companion CI compares immutable Git trees, current source declarations and
the **unchanged** station-access `public-companion-pins.json` accepted
October 22 baseline. It does **not** confer copyright ownership, legal
permission, future wheel/npm/rootfs distribution authority or native access.

## Exact evidence reviewed

| Candidate | Immutable SHA | Accepted / reviewed ancestry | Source delta | Rights/notice declaration |
| --- | --- | --- | --- | --- |
| host-identify 0.3.5 | `4a176373ff4cb47a66a8ab1b5fd3d6ff01ff2a3b` | `1a5eac0b255c995022db6a3a4c0051efffa748cc` | 5 commits / 14 files | Source declarations observed |
| host-discover 0.4.14, PR #2 | `ed63d8df3cb733192c82b60dd95d13389b9922b5` | `ebe83775e9099fd406f6ad9213a42b25bade5b13` | 5 commits | Source declarations observed |
| host-discover 0.4.14, PR #3 | `4653cbffcef627dd8945dcb0d14deac5947e97fa` | Accepted `0f2c6fd5cb33528ed2fe9fd1c855d2f691db6f80` | 18 commits / 25 files | Source declarations observed |
| host-install 0.14.9, PR #11 | `5c03d935be85622789b18559448e1560066d0a37` | Accepted `e6e474c63749a614fcf934d547d70b2bd12d7ce0` | 183 commits / 60 files | Source declarations observed |
| station-access 0.4.29, PR #18 | `7e8829483c1f2d49b2a4e7f2d97c6c2b9e364a73` | PR base `c2540cc5c9a3a0c1fff2748552819685ed2fdff4` | 54 commits / 14 files | Source declarations observed |

The PR #3 ancestry repair is verified: exact PR #2 is an ancestor and its
additional source delta is **only** `credential_delivery.py`, the
credential-delivery boundary documentation and its test. The final PR #3
has no stand-alone GitHub Actions run on its merge head, but station-access
PR #18 checks out that exact immutable commit and exercises the common
Credential-Authority-signed admin identity through the three-owner source
workflow. This is stronger than relying on an unverified reference to an
earlier divergent branch.

All four selected source repositories at the specified heads contain
`LICENSE`, `LICENSES/BSD-3-Clause.txt`,
`LICENSES/GPL-3.0-only.txt`, `THIRD-PARTY-NOTICES.md` and `pyproject.toml`
declaring `BSD-3-Clause OR GPL-3.0-only`. Git blob IDs are recorded per
source in the machine ledger. Existing legal blobs did not change in these
PRs. These files assert a public first-party grant scoped to owned work:
**the public declaration and repository account are not independent proof
that each newly changed source file was created or granted by an authorized
rights holder**. Their text expressly excludes historical private Git
snapshots, third-party code and installed infrastructure.

## Ownership/permission signoff — not independently established

| Evidence requirement | Current disposition |
| --- | --- |
| Original first-party license text and both full option texts | Observed at exact heads |
| Candidate author/committer and source ancestry | Git history observable; commits do not constitute a separately authenticated grant |
| Per-new-head **actual** copyright holder identity/authority for the cumulative delta | **PENDING** independently attributable authorization |
| Externally authored files, imported fragments, generated/source transformations and permission exceptions | **PENDING** owner-confirmed per-file exception inventory |
| Historical private-to-public permission for new public source | **PENDING** explicit original-holder scope check; prior private history is not automatically granted |
| Source consumer exact identity/compatibility | **PASS** in source tests; not native acceptance |
| Independently signed rightsholder acceptance of the new immutable revision set | **PENDING** |

The station-access **candidate** manifest now explicitly uses
`rights_acceptance=pending-independent-owner-attestation`, retaining
`consumer_acceptance=accepted` for passing source interoperation. It does not
assert independent holder authorization of these cumulative revisions. This ledger deliberately uses
`independent_rightsholder_permission=not-attested` and refuses any automatic
conversion from source CI to ownership clearance. Do not reinterpret passing source acceptance as a signed ownership grant.

### Required rightsholder/authorized owner handoff

For **each exact immutable candidate SHA**, attach an independently attributable
approval stating (a) original copyright owner and capacity to grant, (b) which
cumulative new tracked paths are original, licensed from third parties,
or generated, (c) exceptions and supporting upstream source/license or
written permission, (d) exact grant scope and source/license selection,
(e) identity/signature or controlled-review provenance, and (f) precise
reviewed commit and tree. A GitHub comment by a contributor, a public license
file, or a passing CI job alone is insufficient for this separate check.
Reviewing these records is a source rights process, **not** permission to
deploy a root-owned credential authority.

## Distributable dependency notices — boundary and requirements

The declared Python direct dependencies are enumerated **verbatim** from
`pyproject.toml` in the machine ledger: host-identify's crypto,
HTTP-signing/JWT/request stack; host-discover's exact
`host-identify==0.3.5` and `host-install==0.14.9`; and station-access's
Django, Waitress, boto3 and other Zog dependencies. host-install has no
direct Python requirements in its candidate project metadata.

The station-access frontend already contains reviewed September 30 registry
evidence (`frontend/license-evidence.json`) for published npm artifacts,
including React, react-dom, react-router, scheduler and Vite. Build tooling
is configured to emit `dist/assets/LICENSES-*.txt` and
`dist/frontend-build.json` for actual bundled packages and link the
generated notice from HTML. The existing record is not a fresh current
distributable build inventory.

For an **actual future binary release**, an independently audited bill of
materials must cover resolved/transitive wheel distributions (including
licenses, copyright/NOTICE and any source offer), real lockfile vs emitted JS
bundle, all selected Zog companion commit licenses, and native/rootfs
dependency files (kernel, systemd, noVNC/TurboVNC, firmware, libraries).
Record exact versions, immutable artifact digests, primary source and
complete supplied notices, and perform artifact read-back. The source
metadata and current candidate Git trees **cannot determine that complete
set**. The existing source notices explicitly defer it. No aggregate
distribution is cleared by this ledger.

### Consolidated Python wheel-notice evidence (from PR #6)

This PR is the single maintained administrator-credential provenance handoff. PR #6's distinct wheel-byte notice collector `tools/inventory_admin_credential_wheel_notices.py`, synthetic substitutions/missing-license tests `tests/test_source_provenance_inventory.py`, and [wheel receipt](../../verification/administrator-credential/PYTHON-WHEEL-NOTICE-RECEIPT.md) have been incorporated. The duplicate PR #6 source ledger, Git ancestry checker, and second workflow are intentionally **not** copied: the one authoritative source ledger and verifier above already check ancestry, SPDX declarations, immutable legal blobs, 113 changed paths, source selection, and negative rights/native promotion.

The consolidated GitHub Actions workflow downloads the station-access exact-head `requirements-security-tested.txt` Python wheels and separately selected `dbus-next==0.2.3` and compatible `dnspython` into a disposable wheelhouse. The collector records actual wheel SHA-256, distribution metadata, legal-file SHA-256 and supplied full text into the **review-only** `admin-credential-python-wheel-notice-evidence` artifact (`python-wheel-inventory.json` and `PYTHON-WHEEL-NOTICES.txt`). Negative unit tests reject missing, wrong-version, duplicate/unpinned requirements and swapped wheels; missing license metadata or files remain explicitly flagged for manual inspection.

The earlier PR #6 snapshot found 29 wheels and 52 discoverable legal files; these counts describe that earlier acquisition and are **not** presumed to be the fresh consolidated result. Registry bytes and compatible `dnspython` versions may change, so inspect each new workflow artifact and do not use this transient tested environment as an immutable final distribution BOM. The final assembled release still needs matched wheel hashes, notices, copyright exceptions, source-offer obligations and native/npm/rootfs inventory. **No legal clearance or credential delivery is inferred.**

## Current consumer CI and no-repin condition

- host-discover PR #2 exact 0.4.14 compatibility with `python -m pip check`
  on Python 3.12/3.13, namespace and Host identity lanes: GitHub Actions
  `41307288497`, `41307288397`, `41307288438` — **PASS**.
- host-install PR #11 exact revision: admin HTTPS source `41307164907`,
  public source `41307164882` — **PASS**.
- station-access PR #18 **current** exact `7e882948...`: three-owner
  signed-profile `41536187806`, canonical v1 `41536187810` and full
  Public Source Acceptance `41536188085` — all **PASS**.
- PR #3 has no direct CI on its merged head; the station three-owner lane
  checks it out exactly. This is documented instead of inventing a run.

The signed credential identity stays
`consumer=station-access`,
`purpose=station-access-administrator-password`,
`credential_id=station-admin`; Django account ID and revision remain
separately operator-signed. Existing accepted production
`public-companion-pins.json` has blob
`db53b4f56aa26581673dbacb3f4d8ee545a673da` and was **not changed**.

**Disposition:** source declarations, ancestry, documented dependency
edge set and selected consumer compatibility **PASS**. Independently
attributable rights-holder authorization and complete future distributable
notices **PENDING**. Production repinning, native issuer/FD/SCM_RIGHTS
installation, enrollment, real password delivery and Host-signed receipt
remain **NO-GO**. This source review is not a rights grant or native install.


## Independent changed-path ownership inventory (November 2 review extension)

The exact two-tree delta, not merely cumulative file counts, is recorded in
`verification/admin-credential-changed-path-rights-2026-11-02.json`.
Every **113** observed changed paths carries its candidate repository,
accepted/reviewed base, exact head, added/modified/removed/renamed status,
approximate source role and two deliberately pending decisions:
`rightsholder_authorization=pending-per-path-owner-attestation` and
`third_party_or_generated_exception=not-independently-reconciled`.
This includes the renamed host-discover 0.4.14 compatibility test, not just
new files. The existing source ledger checker now independently compares
each recorded change with real `git diff --name-status -M` and refuses a
tampered, unreviewed file-level rights promotion. CI exercises negative
forged owner-grant and third-party-exception cases.

**The path inventory is ready for a rights holder to review; the permission
column is not filled with guessed author identities or legal ownership.**
An authenticated authorized rights-holder assertion for the exact cumulative
paths and a real artifact dependency/NOTICE BOM remain outstanding. Do not
close the rights/distribution authorization gate merely because this source
inventory is now complete.

## Older station-access #17 dependency chain remains separate

Historical station-access PR #12 at
`c2540cc5c9a3a0c1fff2748552819685ed2fdff4` source-checked
host-identify **0.3.5** (`4a176373…`), host-discover **0.4.13**
(`ebe83775…`) and corrected host-install **0.14.3**
(`6e8b3792…`). Its PR body and checked candidate manifest retain
`source-candidate-not-accepted` and rights/native approval PENDING.
The corrected older host-install has C1 package/module/CLI, C2 whole-disk
alias/WWN uniqueness/root exclusion, and C3 inherited-WWN read-only
fixture tests. Station public source and canonical HTTPS workflows passed
at that historical PR #12 head (runs `41119787785`, `41119787853`).

The newer administrator candidate is **not** a silent repin of that older
0.4.13/0.14.3 chain: station-access PR #18 at
`7e8829483c1f2d49b2a4e7f2d97c6c2b9e364a73`
reviews host-discover **0.4.14** (`4653cbff…`) and host-install **0.14.9**
(`5c03d935…`), while both still use canonical host-identify 0.3.5.
The exact-head three-owner FD workflow installs those source candidates
as editable distributions, requires clean `pip check`, checks versions
and actual imported component `__file__` paths against immutable checkouts,
then fails if required negative-security tests are missing or skipped.
Synthetic root/FD fixtures are explicitly identified as non-native; they
cannot substitute an independently authenticated source or signer.

**Disposition:** both selected chains have reviewable source compatibility
evidence and unchanged production pins; neither is a native installation.
The old #17 dependency review can be marked **source evidence reviewed**
without converting the new candidate, legal rights-holder signoff, complete
transitive distribution notices or live protected administrator delivery to
accepted.
