"""Exact-source provenance evidence gate (NOT rights-holder or native approval).

Checks tracked Git source objects, ancestry, package declarations and a
separately immutable accepted manifest. Does not infer legal ownership,
install credentials, edit accepted pins, or clear distribution notices.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "verification/admin-credential-source-provenance-2026-11-02.json"
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
SOURCE_NAMES = ("LICENSE","LICENSES/BSD-3-Clause.txt",
                "LICENSES/GPL-3.0-only.txt","THIRD-PARTY-NOTICES.md",
                "pyproject.toml")


def require(test, why):
    if not test:
        raise ValueError("candidate provenance source HOLD: "+why)


def git(repo, *args):
    return subprocess.check_output(["git","-C",str(repo),*args],
                                   stderr=subprocess.DEVNULL,text=True).strip()


def check(root=ROOT, checkout_root=None, ledger_file=EVIDENCE):
    root=Path(root)
    checkout_root=Path(checkout_root) if checkout_root else root/"candidate"
    ledger=json.loads(Path(ledger_file).read_text())
    require(ledger["schema"]=="zog-administrator-credential-candidate-provenance-v1",
            "unknown evidence schema")
    for field,value in (
        ("independent_rightsholder_permission","not-attested"),
        ("distributable_notice_clearance","not-complete"),
        ("candidate_adoption","not-authorized-by-this-ledger"),
        ("native_credential_installation","not-authorized"),
        ("production_pin_change","forbidden")):
        require(ledger.get(field)==value,"unreviewed promotion of "+field)
    revisions=ledger["revisions"]
    require(len(revisions)==4 and {r["repository"] for r in revisions}=={
        "zog144/host-identify","zog144/host-discover",
        "zog144/host-install","zog144/station-access"},
        "unexpected provenance closure")
    githeads={}
    for item in revisions:
        repo=checkout_root / item["repository"].split("/")[-1]
        require(repo.is_dir(),"missing exact checkout for "+item["repository"])
        require(SHA40.fullmatch(item["commit"]) is not None,
                "revision not full SHA")
        require(git(repo,"rev-parse","HEAD")==item["commit"],
                "wrong exact revision "+item["repository"])
        original=item.get("accepted",item.get("review_base"))
        require(SHA40.fullmatch(original) is not None,
                "missing known source base "+item["repository"])
        require(git(repo,"merge-base","--is-ancestor",original,item["commit"])=="",
                "unrelated source base")
        require(len(git(repo,"rev-list",original+".."+item["commit"]).splitlines())
                ==item["ahead"],"cumulative commit count mismatch")
        changed=[f for f in git(repo,"diff","--name-only",original,
                                item["commit"]).splitlines() if f]
        require(len(changed)==item["change_count"],
                "cumulative source file count mismatch "+item["repository"])
        for name in SOURCE_NAMES:
            require((repo/name).is_file(),
                    "missing declared source legal input "+item["repository"]+"/"+name)
        expect={
            "LICENSE":"license_blob",
            "LICENSES/BSD-3-Clause.txt":"bsd_license_blob",
            "LICENSES/GPL-3.0-only.txt":"gpl_license_blob",
            "THIRD-PARTY-NOTICES.md":"notices_blob",
            "pyproject.toml":"metadata_blob",
        }
        for name,label in expect.items():
            require(git(repo,"hash-object",name)==item[label],
                    "tracked legal/package blob changed "+item["repository"]+"/"+name)
        package=tomllib.loads((repo/"pyproject.toml").read_text())["project"]
        require(package.get("license")==item["declared_spdx"],
                "declared SPDX changed "+item["repository"])
        require(item["independent_rightsholder_permission"]=="pending-owner-evidence"
                and item["distributable_artifact_notices"]==
                    "pending-exact-artifact-manifest",
                "rights or artifacts were silently accepted")
        if "version" in package:
            require(package["version"]==item["version"],
                    "candidate package version drift")
        githeads[item["repository"]]=(repo,package)
    discover=githeads["zog144/host-discover"][0]
    assert_rev=ledger["ancestry"]["host-discover-pr3"]
    require(git(discover,"merge-base","--is-ancestor",
                assert_rev["parent"],"HEAD")=="",
            "repaired PR3 ancestry lost")
    require(git(discover,"merge-base",assert_rev["parent"],"HEAD")==
            assert_rev["parent"],"PR3 merge base changed")
    require(sorted(git(discover,"diff","--name-only",
                       assert_rev["parent"],"HEAD").splitlines())
            ==sorted(assert_rev["delta_paths"]), "profile content drifted")
    require(ledger["compatibility"]["host-discover-requires"]==
            githeads["zog144/host-discover"][1]["dependencies"],
            "host-discover dependency closure shifted")
    station=githeads["zog144/station-access"][0]
    require("host-identify==0.3.5" in
            githeads["zog144/station-access"][1]["dependencies"],
            "station host-identify dependency shifted")
    public=station/"public-companion-pins.json"
    require(git(station,"hash-object",str(public.relative_to(station)))==
            ledger["accepted_public_companion_manifest"]["git_blob"],
            "accepted production companion pins changed")
    accepted=json.loads(public.read_text())
    require(accepted["status"]=="accepted","accepted manifest status mutated")
    candidate=json.loads((station/"credential-v1-companion-candidate.json").read_text())
    require(candidate["status"]=="source-candidate-not-accepted"
            and candidate["rights_acceptance"]=="pending-independent-owner-attestation"
            and candidate["consumer_acceptance"]=="accepted",
            "candidate rights and source acceptance must remain distinct")
    require(all(x["rights_acceptance"]=="pending-independent-owner-attestation"
                and x["consumer_acceptance"]=="accepted"
                and x["native_installation_approval"]=="not-authorized"
                for x in candidate["additional_candidates"]),
            "additional candidate rights or native approval promoted")
    overrides={
        candidate["repository"]:candidate["candidate_commit"],
        **{x["repository"]:x["candidate_commit"]
           for x in candidate["additional_candidates"]}
    }
    for repo,head in overrides.items():
        require(head==dict((x["repository"],x["commit"]) for x in revisions)[repo],
                "candidate immutable selection drifted "+repo)
    for repo,deps in ledger["distribution_scope"]["direct_python_source_packages"].items():
        key="zog144/"+repo
        require(deps==githeads[key][1].get("dependencies",[]),
                "declared Python dependency inventory moved "+key)
    frontend=ledger["distribution_scope"]["frontend"]
    require(git(station,"hash-object",frontend["evidence"].split(
                    "zog144/station-access/")[-1])==frontend["reviewed_blob"],
            "existing frontend license evidence moved")
    require(ledger["distribution_scope"]["status"]==
            "inventory-declared-only-no-physical-distributable-artifact-audited",
            "artifact-level notice clearance improperly claimed")
    return {key:value[0] for key,value in githeads.items()}


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--checkouts",default="candidate")
    args=p.parse_args()
    verified=check(checkout_root=ROOT/args.checkouts)
    print("PASS: immutable source ancestry, declared grants, notices and "
          "compatible candidate selections", sorted(verified))
    print("HOLD: independent rightsholder permission, artifact notices, "
          "production repin, native credential installation")
