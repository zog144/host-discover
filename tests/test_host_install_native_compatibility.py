"""Native ownership/mode checks for the selected host-install state I/O API.

The exact companion workflow runs this file as root on a disposable GitHub
runner. No ownership function is mocked here.
"""
import os
import stat

import pytest

from zog.host_install.state_contract import StateError
from zog.host_install.state_inspect import metadata
from zog.host_install.state_io import ensure_directory, lock, publish, raw


pytestmark = pytest.mark.skipif(
    os.geteuid() != 0,
    reason="native ownership fixture requires root on a disposable runner",
)


def test_native_numeric_state_ownership_and_root_supervisor_publication(tmp_path):
    root_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    host_fd = control_fd = supervisor_fd = None
    try:
        host_fd = ensure_directory(root_fd, "host-discover", 970, 970, 0o700)
        metadata(host_fd, 970, 970, 0o700)

        control_fd = ensure_directory(host_fd, "control", 970, 970, 0o700)
        metadata(control_fd, 970, 970, 0o700)

        supervisor_fd = ensure_directory(
            root_fd, "host-discover-supervisor", 0, 0, 0o700
        )
        metadata(supervisor_fd, 0, 0, 0o700)

        payload = b'{"kind":"native-fixture","schema":1}'
        with lock(supervisor_fd, "lock"):
            publish(supervisor_fd, "ledger.json", payload)
        assert raw(supervisor_fd, "ledger.json") == payload
        info = os.stat(
            "ledger.json", dir_fd=supervisor_fd, follow_symlinks=False
        )
        assert stat.S_ISREG(info.st_mode)
        assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (
            0, 0, 0o600
        )
    finally:
        for fd in (supervisor_fd, control_fd, host_fd, root_fd):
            if fd is not None:
                os.close(fd)


def test_native_existing_wrong_ownership_is_rejected_without_repair(tmp_path):
    path = tmp_path / "host-discover"
    path.mkdir(mode=0o755)
    os.chown(path, 0, 0)
    before = path.lstat()

    root_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(StateError):
            ensure_directory(root_fd, "host-discover", 970, 970, 0o700)
    finally:
        os.close(root_fd)

    after = path.lstat()
    assert (after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)) == (
        before.st_uid,
        before.st_gid,
        stat.S_IMODE(before.st_mode),
    )
    assert (after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)) == (
        0, 0, 0o755
    )
