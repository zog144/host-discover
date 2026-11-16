"""Explicit fresh legacy-format identity in a directory-backed /state.

Do not use host-identify's legacy loader: it intentionally rejects /state.
This path creates a key *only* in an empty, owned, symlink-safe identity
directory and persists a locally generated origin/key marker. Later starts
may reuse only that marked key, never an unmarked legacy or managed identity.
"""
import fcntl
import json
import os
import stat
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zog.host_identify.initialization import (
    IdentityStateError, directory_fd, create, decode_key, read,
)
from zog.host_identify.signatures import fingerprint, origin

MARKER = "fresh-state-bootstrap.json"
INITIAL = frozenset()
CREATED = frozenset({"key.lock", "identity.pem", MARKER})
ENROLLED = CREATED | {"binding.json"}


def _regular(fd, name):
    handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        info = os.fstat(handle)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_gid != os.getegid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 32768):
            raise PermissionError("Unsafe freshly bootstrapped identity file")
    finally:
        os.close(handle)


def _marker(key, registry):
    return {"schema": "zog-host-discover-fresh-state-bootstrap-v1",
            "registry_origin": origin(registry),
            "fingerprint": fingerprint(key.public_key())}


def _validate(fd, registry):
    names = set(os.listdir(fd))
    if names not in (CREATED, ENROLLED):
        raise IdentityStateError("Fresh STATE identity is incomplete or contains foreign state")
    for name in names:
        _regular(fd, name)
    key = decode_key(read(fd, "identity.pem"))
    try:
        marker = json.loads(read(fd, MARKER))
    except (ValueError, TypeError, UnicodeError) as error:
        raise IdentityStateError("Invalid fresh STATE identity provenance") from error
    if type(marker) is not dict or marker != _marker(key, registry):
        raise IdentityStateError("Existing identity does not belong to this fresh registry")
    if "binding.json" in names:
        try:
            binding = json.loads(read(fd, "binding.json"))
        except (ValueError, TypeError, UnicodeError) as error:
            raise IdentityStateError("Invalid saved Host binding") from error
        if (type(binding) is not dict or set(binding) != {"host_id", "fingerprint"}
                or binding["fingerprint"] != marker["fingerprint"]):
            raise IdentityStateError("Saved Host binding conflicts with fresh identity")
        import uuid
        try:
            if str(uuid.UUID(binding["host_id"])) != binding["host_id"]:
                raise ValueError()
        except (ValueError, TypeError, AttributeError) as error:
            raise IdentityStateError("Invalid saved Host UUID") from error
    return key


def load_or_create(root, registry, *, claimed_host_id=None):
    """Create only on empty /state; reuse only this previously generated key.

    Directory provisioning is an installer responsibility: absent directories
    are not created here. Never adopts an existing unmarked key/binding.
    """
    if not isinstance(root, str) or not root.startswith("/state/"):
        raise IdentityStateError("Explicit canonical /state identity directory required")
    if os.path.normpath(root) != root or "//" in root:
        raise IdentityStateError("Noncanonical STATE identity path")
    registry = origin(registry)
    with directory_fd(root) as fd:
        names = set(os.listdir(fd))
        if names == INITIAL:
            if claimed_host_id:
                raise IdentityStateError("New STATE identity cannot claim an existing Host UUID")
            # Exclusive O_EXCL lock creation refuses concurrent bootstrap. A
            # crash after this step leaves incomplete state, never a new key.
            lock_fd = os.open("key.lock", os.O_CREAT | os.O_EXCL | os.O_RDWR |
                              os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                if set(os.listdir(fd)) != {"key.lock"}:
                    raise IdentityStateError("Concurrent or foreign bootstrap")
                key = Ed25519PrivateKey.generate()
                secret = key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption())
                create(fd, "identity.pem", secret)
                create(fd, MARKER, (json.dumps(_marker(key, registry),
                      sort_keys=True, separators=(",", ":")) + "\n").encode())
                os.fsync(fd)
                return _validate(fd, registry)
            finally:
                os.close(lock_fd)
        if names not in (CREATED, ENROLLED):
            raise IdentityStateError("Existing identity cannot be adopted as a fresh bootstrap")
        _regular(fd, "key.lock")
        lock_fd = os.open("key.lock", os.O_RDONLY | os.O_NOFOLLOW |
                          os.O_NONBLOCK, dir_fd=fd)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_SH)
            key = _validate(fd, registry)
            if claimed_host_id:
                if "binding.json" not in set(os.listdir(fd)):
                    raise IdentityStateError("Claimed Host UUID lacks a verified new enrollment")
                binding = json.loads(read(fd, "binding.json"))
                if binding["host_id"] != claimed_host_id:
                    raise IdentityStateError("Configured Host UUID differs from new enrollment")
            return key
        finally:
            os.close(lock_fd)
