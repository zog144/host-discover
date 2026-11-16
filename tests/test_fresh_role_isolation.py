"""Role files never occupy freshly initialized identity storage."""
import json
import os
import stat
import uuid
from pathlib import Path

import pytest
from zog.host_discover import daemon
from zog.host_discover.roles import Controller
from zog.host_identify.signatures import fingerprint


@pytest.fixture
def isolated_state():
    state = Path("/state")
    created_state = not state.exists()
    if created_state:
        state.mkdir(mode=0o755)
    elif state.is_symlink() or not state.is_dir():
        pytest.skip("unsafe test runner /state")
    base = state / ("fresh-role-test-" + str(uuid.uuid4()))
    identity = base / "identity"
    role = base / "roles"
    identity.mkdir(parents=True, mode=0o700)
    role.mkdir(mode=0o700)
    try:
        yield identity, role
    finally:
        import shutil
        shutil.rmtree(base)
        if created_state:
            state.rmdir()


def config(identity):
    return {"server":"https://new-registry.example.invalid",
            "identity_directory":str(identity),
            "credential_directory":"/var/lib/host-discover/credentials",
            "provider":"generic", "identity_mode":"legacy-bootstrap"}


def test_role_state_separated_and_existing_key_preserved(isolated_state):
    identity, role = isolated_state
    cfg = config(identity)
    first = fingerprint(daemon.identity_key(cfg).public_key())
    original = {p.name:(p.stat().st_ino,p.read_bytes())
                for p in identity.iterdir()}
    controller = Controller(cfg)
    assert controller.root == role
    assert controller.tick()["state"] == "stopped"
    assert (role/"mirror-role.lock").is_file()
    assert not any(p.name.startswith("mirror-role") for p in identity.iterdir())
    assert fingerprint(daemon.identity_key(cfg).public_key()) == first
    assert {p.name:(p.stat().st_ino,p.read_bytes())
            for p in identity.iterdir()} == original
    assert not (identity/"binding.json").exists()


def test_prior_role_files_moved_same_inode_without_reenrollment(isolated_state):
    identity, role = isolated_state
    cfg = config(identity)
    before_fp = fingerprint(daemon.identity_key(cfg).public_key())
    for name, data in (("mirror-role.lock",b""),("mirror-role.json",b'{}')):
        p = identity/name
        p.write_bytes(data)
        p.chmod(0o600)
    originals = {name:(identity/name).stat().st_ino
                 for name in ("mirror-role.lock","mirror-role.json")}
    assert fingerprint(daemon.identity_key(cfg).public_key()) == before_fp
    Controller(cfg)
    assert {name:(role/name).stat().st_ino for name in originals} == originals
    assert not any(name in os.listdir(identity) for name in originals)
    assert fingerprint(daemon.identity_key(cfg).public_key()) == before_fp
    assert not (identity/"binding.json").exists()


@pytest.mark.parametrize("unsafe", ["symlink","hardlink","wrong-mode","wrong-owner","conflict"])
def test_unsafe_existing_role_file_migration_fails_closed(isolated_state, unsafe):
    identity, role = isolated_state
    cfg = config(identity)
    key_fp = fingerprint(daemon.identity_key(cfg).public_key())
    old = identity/"mirror-role.json"
    old.write_text("{}")
    old.chmod(0o600)
    if unsafe == "symlink":
        old.unlink()
        old.symlink_to(identity/"identity.pem")
    elif unsafe == "hardlink":
        os.link(old, identity.parent/"duplicate")
    elif unsafe == "wrong-mode":
        old.chmod(0o666)
    elif unsafe == "wrong-owner":
        os.chown(old, 10001, -1)
    else:
        (role/"mirror-role.json").write_text("{}")
        (role/"mirror-role.json").chmod(0o600)
    with pytest.raises((OSError,ValueError,PermissionError)):
        Controller(cfg)
    assert (identity/"identity.pem").exists()
    # Repair only the disposable fixture; never recover by replacing the key.
    if unsafe=="wrong-owner":
        os.chown(old, os.geteuid(), -1)
    if unsafe=="symlink":
        old.unlink()
    else:
        if unsafe=="hardlink":
            (identity.parent/"duplicate").unlink()
        if unsafe=="wrong-mode":
            old.chmod(0o600)
        if unsafe=="conflict":
            (role/"mirror-role.json").unlink()
        old.unlink()
    assert fingerprint(daemon.identity_key(cfg).public_key()) == key_fp


def test_missing_role_directory_never_changes_identity(isolated_state):
    identity, role = isolated_state
    cfg = config(identity)
    first = fingerprint(daemon.identity_key(cfg).public_key())
    role.rmdir()
    with pytest.raises((OSError,ValueError,PermissionError)):
        Controller(cfg)
    assert fingerprint(daemon.identity_key(cfg).public_key()) == first
