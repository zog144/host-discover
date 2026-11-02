#!/usr/bin/env python3
"""Read-only verification of *observed* provenance, not legal rights approval.

The exact revisions in this ledger are intentionally fixed. All candidate source
checkouts must be public, clean, and at the declared immutable Git commit.
"""
import argparse
import json
import re
import subprocess
import tomllib
from pathlib import Path

LEDGER = Path(__file__).resolve().parents[1] / "verification/administrator-credential/source-provenance-2026-11-02.json"
COPYRIGHT_PATHS = {
    "license_git_blob": "LICENSE",
    "notices_git_blob": "THIRD-PARTY-NOTICES.md",
    "pyproject_git_blob": "pyproject.toml",
}
COMPONENT_DIRS = {
    "zog144/host-identify": "host-identify",
    "zog144/host-install": "host-install",
    "zog144/station-access": "station-access",
}
COMMON_LEGAL = {
    "LICENSES/BSD-3-Clause.txt": "7e1ffb223693647c1750e550d9fd7ee94ce4ee0b",
    "LICENSES/GPL-3.0-only.txt": "f6cdd22a6c1fbc887e08a215cb4beb3c47048041",
}
DECLARATION = "BSD-3-Clause OR GPL-3.0-only"


def git(path, *args, check=True):
    result = subprocess.run(["git", "-C", str(path), *args], capture_output=True,
                            text=True, check=check)
    return result.stdout.strip()


def location(candidate, root):
    if candidate["repository"] == "zog144/host-discover":
        suffix = ("host-discover-profile"
                  if candidate.get("role") == "administrator-profile"
                  else "host-discover-dependency")
    else:
        suffix = COMPONENT_DIRS[candidate["repository"]]
    return root / suffix


def verify_source(ledger, root):
    if ledger["schema"] != "zog-administrator-credential-source-provenance-v1":
        raise ValueError("wrong provenance schema")
    if ledger["owner_rights_verification"] != "pending-independent-per-revision-attestation":
        raise ValueError("an evidence inventory must not award ownership permission")
    if "hold" not in ledger["disposition"]:
        raise ValueError("distribution hold was silently lifted")
    if ledger["common_license_text_git_blobs"] != COMMON_LEGAL:
        raise ValueError("legal text digest drift")
    if len(ledger["candidates"]) != 5:
        raise ValueError("exact five source heads required")
    seen = set()
    for entry in ledger["candidates"]:
        identity = (entry["repository"], entry.get("role", ""))
        if identity in seen:
            raise ValueError(f"duplicate source identity: {identity}")
        seen.add(identity)
        source = location(entry, root)
        if git(source, "rev-parse", "HEAD") != entry["commit"]:
            raise ValueError(f"wrong exact source: {identity}")
        if git(source, "status", "--porcelain"):
            raise ValueError(f"dirty selected source: {identity}")
        lineage = subprocess.run(["git", "-C", str(source), "merge-base",
                                  "--is-ancestor", entry["base"], entry["commit"]],
                                 capture_output=True)
        if lineage.returncode:
            raise ValueError(f"non-descendant source: {identity}")
        if "required_parent" in entry:
            parents = git(source, "show", "-s", "--format=%P", entry["commit"]).split()
            if entry["required_parent"] not in parents:
                raise ValueError("administrator profile lost exact dependency parent")
        for field, path in COPYRIGHT_PATHS.items():
            actual = git(source, "hash-object", path)
            if actual != entry[field]:
                raise ValueError(f"reviewed source drift: {identity} {path}")
        for path, expected in COMMON_LEGAL.items():
            if git(source, "hash-object", path) != expected:
                raise ValueError(f"reviewed license text drift: {identity} {path}")
        license_text = (source / "LICENSE").read_text(encoding="utf-8")
        project = tomllib.loads((source / "pyproject.toml").read_text(encoding="utf-8"))
        if DECLARATION not in license_text or project["project"]["license"] != DECLARATION:
            raise ValueError(f"missing explicit source grant: {identity}")
        if project["project"].get("version") not in (entry["version"], None):
            raise ValueError(f"unexpected package version: {identity}")
        if entry["repository"] == "zog144/host-identify":
            mod = (source / "src/zog/host_identify/__init__.py").read_text()
            if f'__version__ = "{entry["version"]}"' not in mod:
                raise ValueError("host-identify version attribute mismatch")
        if "pending" not in entry["status"]:
            raise ValueError(f"source rights status was silently promoted: {identity}")
        changed = git(source, "diff", "--name-only", entry["base"], entry["commit"]).splitlines()
        prohibited = (".whl", ".zip", ".tar", ".tar.gz", ".so", ".dll", ".exe", ".png", ".jpg",
                      ".woff", ".woff2", ".pdf")
        if any(p.lower().endswith(prohibited) for p in changed):
            raise ValueError(f"binary/vendored-asset delta needs independent review: {identity}")
        print(f"OBSERVED {entry['repository']} {entry.get('role', '')}: {entry['commit']}; "
              f"source/license/notice hashes verified, owner attestation PENDING")

    station = root / "station-access"
    baseline = git(station, "hash-object", "public-companion-pins.json")
    if baseline != "db53b4f56aa26581673dbacb3f4d8ee545a673da":
        raise ValueError("accepted production source pins were changed")
    for name, expected in (
        ("requirements-security-tested.txt", ledger["distributable_inputs"]["station_python_tested_requirements_git_blob"]),
        ("frontend/license-evidence.json", ledger["distributable_inputs"]["station_frontend_reviewed_evidence_git_blob"]),
    ):
        if git(station, "hash-object", name) != expected:
            raise ValueError(f"external distribution-input evidence drift: {name}")
    profile = next(e for e in ledger["candidates"]
                   if e.get("role") == "administrator-profile")
    install = next(e for e in ledger["candidates"]
                   if e["repository"] == "zog144/host-install")
    identify = next(e for e in ledger["candidates"]
                    if e["repository"] == "zog144/host-identify")
    project = tomllib.loads((location(profile, root) / "pyproject.toml").read_text())
    if set(project["project"]["dependencies"]) != {
        f"host-identify=={identify['version']}",
        f"host-install=={install['version']}",
    }:
        raise ValueError("exact administrator consumer dependency closure changed")
    print("PASS observed candidate provenance and immutable production manifest; "
          "rights-holder proof and actual release notice clearance remain PENDING")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkouts", type=Path, required=True,
                        help="Directory with five pinned, full-history source checkouts")
    args = parser.parse_args()
    verify_source(json.loads(LEDGER.read_text(encoding="utf-8")), args.checkouts)


if __name__ == "__main__":
    main()
