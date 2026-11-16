"""Fresh legacy-format /state bootstrap, not retained Host migration.

All /state paths are disposable synthetic CI paths; no existing Host touched.
"""
import json
import os
import stat
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from zog.host_discover import daemon
from zog.host_discover.fresh_state_identity import MARKER
from zog.host_identify.signatures import fingerprint


@pytest.fixture
def state_identity():
    state = Path("/state")
    created_state = not state.exists()
    if created_state:
        state.mkdir(mode=0o755)
    elif state.is_symlink() or not state.is_dir():
        pytest.skip("Unsafe pre-existing /state on disposable test host")
    workspace = state / ("host-discover-fresh-test-" + str(uuid.uuid4()))
    workspace.mkdir(mode=0o700)
    root = workspace / "identity"
    root.mkdir(mode=0o700)
    try:
        yield root
    finally:
        import shutil
        shutil.rmtree(workspace)
        if created_state:
            state.rmdir()


def config(root):
    return {"identity_mode":"legacy-bootstrap",
            "identity_directory":str(root),
            "credential_directory":"/var/lib/host-discover/credentials",
            "server":"https://new-registry.example.invalid",
            "provider":"generic"}


def test_setup_when_state_already_exists_or_installer_creates_it(state_identity):
    root = state_identity
    cfg = config(root)
    assert daemon.validate_configuration(cfg) is cfg
    with patch("zog.host_identify.storage.load_key",
               side_effect=AssertionError("must not use legacy loader")):
        key = daemon.identity_key(cfg)
        second = daemon.identity_key(cfg)
    assert fingerprint(key.public_key()) == fingerprint(second.public_key())
    assert set(p.name for p in root.iterdir()) == {
        "identity.pem", "key.lock", MARKER}
    assert stat.S_IMODE((root / "identity.pem").stat().st_mode) == 0o600
    assert not (root / "binding.json").exists()


def test_preexisting_key_and_saved_binding_are_never_adopted(state_identity):
    root = state_identity
    (root / "identity.pem").write_text("old-secret")
    (root / "identity.pem").chmod(0o600)
    (root / "binding.json").write_text('{"host_id":"foreign","fingerprint":"foreign"}')
    (root / "binding.json").chmod(0o600)
    with pytest.raises(daemon.IdentityUnavailableError):
        daemon.identity_key(config(root))
    assert (root / "identity.pem").read_text() == "old-secret"


@pytest.mark.parametrize("foreign", ["lock-only", "key-only", "binding-only",
                                      "managed-receipt", "unexpected-file"])
def test_incomplete_or_foreign_state_is_rejected(state_identity, foreign):
    root = state_identity
    filename = {"lock-only":"key.lock", "key-only":"identity.pem",
                "binding-only":"binding.json", "managed-receipt":"receipt.json",
                "unexpected-file":"alien"}[foreign]
    (root / filename).write_bytes(b"anything")
    (root / filename).chmod(0o600)
    with pytest.raises(daemon.IdentityUnavailableError):
        daemon.identity_key(config(root))


@pytest.mark.parametrize("attack", ["symlink-directory", "world-writable-parent",
                                    "wrong-owner", "foreign-key-link",
                                    "corrupt-marker", "foreign-registry",
                                    "foreign-binding", "symlink-key"])
def test_unsafe_or_substituted_paths_fail_closed(state_identity, attack):
    root = state_identity
    cfg = config(root)
    if attack == "symlink-directory":
        bad = root.parent / "linked"
        bad.symlink_to(root, target_is_directory=True)
        cfg["identity_directory"] = str(bad)
    elif attack == "world-writable-parent":
        root.parent.chmod(0o777)
    elif attack == "wrong-owner":
        os.chown(root, 10001, -1)
    else:
        daemon.identity_key(cfg)
        if attack == "foreign-key-link":
            os.link(root / "identity.pem", root.parent / "linked-key")
        elif attack == "corrupt-marker":
            (root / MARKER).write_text("{}")
        elif attack == "foreign-registry":
            cfg["server"] = "https://different-registry.example.invalid"
        elif attack == "foreign-binding":
            (root / "binding.json").write_text(
                json.dumps({"host_id":str(uuid.uuid4()),"fingerprint":"0"*64}))
            (root / "binding.json").chmod(0o600)
        elif attack == "symlink-key":
            (root / "identity.pem").unlink()
            (root / "identity.pem").symlink_to(root.parent / "absent")
    try:
        with pytest.raises((daemon.IdentityUnavailableError, PermissionError)):
            daemon.identity_key(cfg)
    finally:
        if attack == "wrong-owner":
            os.chown(root, os.geteuid(), -1)
        if attack == "world-writable-parent":
            root.parent.chmod(0o700)


def test_new_registry_receives_genuine_unbound_enrollment(state_identity):
    cfg = config(state_identity)
    attempted = []
    def sign(url, body, key, host_id):
        attempted.append((url, json.loads(body), host_id, fingerprint(key.public_key())))
        return SimpleNamespace(url=url, body=body, headers={})
    class Reply:
        status = 202
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, n): return b'{"status":"pending"}'
    opener = SimpleNamespace(open=lambda request, timeout: Reply())
    with patch("zog.host_identify.signatures.sign", side_effect=sign), \\
         patch("zog.host_discover.daemon.urllib.request.build_opener",
               return_value=opener), \\
         patch("zog.host_identify.storage.purge_expired"), \\
         patch("zog.host_identify.storage.clear_credentials"), \\
         patch("zog.host_discover.roles.Controller") as controller:
        daemon.announce(cfg, {"version":1})
    assert len(attempted) == 1
    url, payload, subject, signing_fp = attempted[0]
    assert url == cfg["server"] + "/api/hosts/enrollment/"
    assert subject == "pending" and payload["claimed_host_id"] == ""
    assert payload["public_key"] and signing_fp == json.loads(
        (state_identity / MARKER).read_text())["fingerprint"]
    assert not (state_identity / "binding.json").exists()
