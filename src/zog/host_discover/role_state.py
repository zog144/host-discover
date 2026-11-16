"""Separate persistent role/controller files from fresh /state identity material.

This module is only selected for fresh directory-STATE bootstrap. An existing
key and its pending enrollment remain untouched. A narrow compatibility move
retains any role files created by the earlier daemon inside the identity tree.
"""
import fcntl
import os
import stat
from pathlib import Path

from zog.host_identify import storage
from zog.host_identify.initialization import directory_fd

ROLE_FILES = frozenset(("mirror-role.json", "mirror-role.lock"))


def _check_regular(dirfd, name):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(name, flags, dir_fd=dirfd)
    try:
        s = os.fstat(fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid()
                or s.st_gid != os.getegid() or s.st_nlink != 1
                or stat.S_IMODE(s.st_mode) != 0o600 or s.st_size > 32768):
            raise PermissionError("Unsafe old role/controller state")
        return s.st_dev, s.st_ino
    finally:
        os.close(fd)


def role_directory(configuration):
    identity = Path(configuration["identity_directory"])
    if (configuration.get("identity_mode", "legacy-bootstrap") != "legacy-bootstrap"
            or not identity.is_relative_to("/state")):
        return storage.directory(identity)
    if not identity.is_absolute() or str(identity) != os.path.normpath(identity):
        raise PermissionError("Noncanonical identity path")
    # The installer prepares /state/host-discover/roles independently, owner
    # 0700. It must not create the directory inside identity.
    target = identity.parent / "roles"
    with directory_fd(str(identity)) as src, directory_fd(str(target)) as dst:
        if os.fstat(src).st_dev != os.fstat(dst).st_dev:
            raise PermissionError("Role-state relocation crosses filesystems")
        lock = os.open(".migration.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                       0o600, dir_fd=dst)
        try:
            s = os.fstat(lock)
            if (not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid()
                    or s.st_gid != os.getegid() or s.st_nlink != 1
                    or stat.S_IMODE(s.st_mode) != 0o600):
                raise PermissionError("Unsafe role-state migration lock")
            fcntl.flock(lock, fcntl.LOCK_EX)
            for name in ROLE_FILES:
                if name not in os.listdir(src):
                    continue
                old_inode = _check_regular(src, name)
                if name in os.listdir(dst):
                    raise PermissionError("Conflicting role state after bootstrap")
                os.rename(name, name, src_dir_fd=src, dst_dir_fd=dst)
                new_inode = _check_regular(dst, name)
                if old_inode != new_inode:
                    raise PermissionError("Role state inode changed during relocation")
                os.fsync(dst)
                os.fsync(src)
        finally:
            os.close(lock)
    return storage.directory(target)
