"""Exact public host-install 0.10.0 compatibility contract.

These tests intentionally validate the selected immutable companion's real API
rather than weakening dependency metadata to satisfy pip resolution.
"""
import inspect
import json
from importlib import metadata
from pathlib import Path

import zog.host_install as host_install
from zog.host_install import (
    state_admission,
    state_contract,
    state_gate,
    state_inspect,
    state_io,
    state_probe,
)

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "tests" / "fixtures" / "host-install" / "bundle.json"


def test_selected_host_install_version_is_exact():
    assert host_install.__version__ == "0.10.0"
    assert metadata.version("host-install") == "0.10.0"


def test_state_contract_keeps_host_discover_numeric_ownership():
    assert state_contract.PROFILE == "zog-host-accounts-v1"
    assert state_contract.PATHS == {
        "mount_point": "/state",
        "identity_directory": "/state/host-discover/identity",
        "trust_directory": "/state/host-discover/trust",
        "control_directory": "/state/host-discover/control",
    }
    assert state_contract.ACCOUNTS["users"]["host-discover"] == {
        "uid": 970,
        "gid": 970,
        "groups": [972, 973],
    }
    assert state_contract.ACCOUNTS["groups"]["archive-consumers"] == 972
    assert state_contract.ACCOUNTS["groups"]["host-control"] == 973


def test_retained_host_install_fixture_validates_under_010_contract():
    bundle = json.loads(BUNDLE.read_text())
    assert state_contract.validate(bundle) is None


def test_host_discover_imported_host_install_api_surface_is_present():
    expected = {
        state_admission: ["observe", "bindings", "request_live", "serve_listener"],
        state_contract: [
            "canonical", "decode", "fields", "header", "require", "sha", "validate"
        ],
        state_gate: ["decide"],
        state_inspect: [
            "directory", "metadata", "read_at", "inspect_live",
            "host_generation_report",
        ],
        state_io: ["ensure_directory", "publish", "raw", "lock"],
        state_probe: ["probe_live"],
    }
    for module, names in expected.items():
        for name in names:
            assert callable(getattr(module, name, None)), (module.__name__, name)


def test_state_io_call_shapes_match_host_discover_usage():
    ensure = inspect.signature(state_io.ensure_directory)
    assert list(ensure.parameters) == [
        "fd", "name", "uid", "gid", "mode", "checkpoint"
    ]
    publish = inspect.signature(state_io.publish)
    assert list(publish.parameters) == [
        "fd", "name", "data", "mode", "uid", "gid", "checkpoint"
    ]
    raw = inspect.signature(state_io.raw)
    assert list(raw.parameters) == [
        "fd", "name", "uid", "gid", "mode", "links"
    ]
    metadata_signature = inspect.signature(state_inspect.metadata)
    assert list(metadata_signature.parameters) == [
        "fd", "uid", "gid", "mode", "is_directory"
    ]
