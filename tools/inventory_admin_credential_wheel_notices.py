#!/usr/bin/env python3
"""Inventory the *downloaded wheel bytes* and their supplied legal notices.

This is an evidence generator, not legal clearance: missing notices, exception
terms, source-offer requirements and eventual release contents need review.
It deliberately never loads or sends operational Zog secrets or credentials.
"""
import argparse
import hashlib
import json
import re
import zipfile
from email.parser import BytesParser
from email.policy import default
from pathlib import Path

NAME = re.compile(r"[-_.]+")
PIN = re.compile(r"^([a-zA-Z0-9_.-]+)==([^\s;]+)$")
LEGAL = re.compile(r"^(LICEN[CS]E(?:[._-].*)?|COPYING(?:[._-].*)?|"
                   r"NOTICE(?:[._-].*)?|COPYRIGHT(?:[._-].*)?|"
                   r"AUTHORS?(?:[._-].*)?|THIRD[-_]PARTY.*)$", re.I)


def normalized(name):
    return NAME.sub("-", name).lower()


def expected_packages(requirements):
    results = {}
    for line in requirements.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = PIN.fullmatch(line)
        if not match:
            raise ValueError(f"unreviewable unpinned requirement: {line!r}")
        name, version = match.groups()
        key = normalized(name)
        if key in results:
            raise ValueError(f"duplicate Python requirement {key}")
        results[key] = version
    return results


def legal_path(path):
    if path.endswith("/"):
        return False
    part = path.split("/")[-1]
    if LEGAL.fullmatch(part):
        return True
    return ".dist-info/licenses/" in path.lower()


def inspect_wheels(wheelhouse, expected):
    seen = {}
    for file in sorted(wheelhouse.glob("*.whl")):
        raw = file.read_bytes()
        with zipfile.ZipFile(file) as zipped:
            metadata_files = [p for p in zipped.namelist()
                              if p.endswith(".dist-info/METADATA")]
            if len(metadata_files) != 1:
                raise ValueError(f"wheel has ambiguous METADATA: {file.name}")
            metadata = BytesParser(policy=default).parsebytes(zipped.read(metadata_files[0]))
            name = normalized(str(metadata["Name"]))
            version = str(metadata["Version"])
            if not name or name in seen:
                raise ValueError(f"duplicate or unnamed wheel: {file.name}")
            if name not in expected or version != expected[name]:
                raise ValueError(f"unselected wheel: {file.name} ({name}=={version})")
            declaration = str(metadata.get("License-Expression") or "").strip()
            if not declaration:
                declaration = str(metadata.get("License") or "").strip()
            if not declaration:
                declaration = "; ".join(str(x) for x in metadata.get_all("Classifier", [])
                                        if str(x).startswith("License ::"))
            notices = []
            for path in sorted(p for p in zipped.namelist() if legal_path(p)):
                data = zipped.read(path)
                if len(data) > 2_000_000:
                    raise ValueError(f"oversized legal file: {name}/{path}")
                notices.append({
                    "path": path,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "bytes": len(data),
                    "text": data.decode("utf-8", errors="replace"),
                })
            seen[name] = {
                "name": name,
                "version": version,
                "wheel_filename": file.name,
                "wheel_sha256": hashlib.sha256(raw).hexdigest(),
                "license_metadata": declaration[:300],
                "notices": notices,
                "review_status": "observed-needs-manual-redistribution-review",
            }
    missing = sorted(set(expected) - set(seen))
    if missing:
        raise ValueError(f"wheelhouse lacks selected distributions: {missing}")
    if not seen:
        raise ValueError("no selected wheels")
    return seen


def write_evidence(install, output):
    output.mkdir(parents=True, exist_ok=True)
    short = {}
    text = [
        "Candidate administrator-credential Python wheel notice inventory",
        "Actual wheel bytes and supplied legal-text files; not full distribution clearance.",
        "No Zog runtime/rootfs/npm artifact is covered by this Python-only bundle.",
        "",
    ]
    for name, entry in sorted(install.items()):
        info = {k: v for k, v in entry.items() if k != "notices"}
        info["notices"] = [{k: v for k, v in notice.items() if k != "text"}
                           for notice in entry["notices"]]
        short[name] = info
        text += [f"===== {name}=={entry['version']} =====",
                 f"wheel: {entry['wheel_filename']}",
                 f"wheel_sha256: {entry['wheel_sha256']}",
                 f"declared_license_metadata: {entry['license_metadata'] or 'NOT DECLARED'}"]
        if not entry["notices"]:
            text += ["NO LEGAL FILE OBSERVED IN WHEEL — MANUAL REVIEW REQUIRED", ""]
        for notice in entry["notices"]:
            text += [f"----- {notice['path']} (sha256:{notice['sha256']}) -----",
                     notice["text"], ""]
    incomplete = [key for key, value in short.items()
                  if not value["notices"] or not value["license_metadata"]]
    manifest = {
        "schema": "zog-administrator-credential-wheel-notices-v1",
        "status": "wheel-artifact-observation-only-no-publication-approval",
        "python_packages": short,
        "count": len(short),
        "manual_review_required": incomplete,
        "excluded": ["actual release-build Zog wheel", "npm/browser build",
                     "rootfs, kernel, Certbot, VNC/native tools", "source offers"],
    }
    (output / "python-wheel-inventory.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "PYTHON-WHEEL-NOTICES.txt").write_text(
        "\n".join(text), encoding="utf-8")
    print(f"Observed {len(short)} exact wheels; manual missing-metadata/notices: {incomplete}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    selected = expected_packages(args.requirements)
    # CI-only companions are included for observation, not pinned by station's
    # requirements file. Their exact resolved versions are recorded in output.
    extra = {"dbus-next": "0.2.3"}
    resolved = {}
    for p in args.wheelhouse.glob("*.whl"):
        with zipfile.ZipFile(p) as archive:
            met = [x for x in archive.namelist() if x.endswith(".dist-info/METADATA")]
            if len(met) != 1:
                raise ValueError(f"wheel metadata ambiguous: {p.name}")
            md = BytesParser(policy=default).parsebytes(archive.read(met[0]))
            name = normalized(str(md["Name"]))
            if name in {"dbus-next", "dnspython"}:
                resolved[name] = str(md["Version"])
    for key, value in extra.items():
        if resolved.get(key) != value:
            raise ValueError(f"missing exact companion {key}=={value}")
    if "dnspython" not in resolved or "dnspython" in selected:
        raise ValueError("missing uniquely selected dnspython companion")
    selected.update(resolved)
    write_evidence(inspect_wheels(args.wheelhouse, selected), args.output)


if __name__ == "__main__":
    main()
