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
| station-access 0.4.29, PR #18 | `a7faf74b23478f473cfb7908306bdc2dd5b3cffc` | PR base `c2540cc5c9a3a0c1fff2748552819685ed2fdff4` | 47 commits / 13 files | Source declarations observed |

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

The older station-access **candidate** manifest uses
`rights_acceptance=accepted` to mean its previously recorded **source
declarations/consumer review**. That is **not** independent holder authorization
of these cumulative new source revisions. This ledger deliberately uses
`independent_rightsholder_permission=not-attested` and refuses any automatic
conversion from source CI to ownership clearance. Do not retroactively
reinterpret the existing candidate source acceptance as a signed ownership
grant.

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

## Current consumer CI and no-repin condition

- host-discover PR #2 exact 0.4.14 compatibility with `python -m pip check`
  on Python 3.12/3.13, namespace and Host identity lanes: GitHub Actions
  `41307288497`, `41307288397`, `41307288438` — **PASS**.
- host-install PR #11 exact revision: admin HTTPS source `41307164907`,
  public source `41307164882` — **PASS**.
- station-access PR #18 **current** exact `a7faf74b...`: three-owner
  signed-profile `41312415374`, canonical v1 `41312415375` and full
  Public Source Acceptance `41312415358` — all **PASS**.
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
