"""Independent, root-installed binding for the already approved managed Host.

This record is an operator expectation, not a station response or credential
authorization. It is never created or replaced by host-discover.
"""
import os
import stat
from zog.host_install.state_contract import decode, header, require, sha
from zog.host_install.state_inspect import read_at
from zog.host_identify import managed, signatures

PATH = "/etc/zog/host-install/managed-station-binding.json"


def validate(value, bootstrap):
    header(value, "zog-managed-station-binding",
           "host_id fingerprint installation_id state_volume_id authority_id registry_id origin station_key_id")
    for name in ("host_id", "installation_id", "state_volume_id", "authority_id"):
        managed.identifier(value[name])
    sha(value["fingerprint"])
    sha(value["station_key_id"])
    reg = bootstrap["registries"][0]
    require(len(bootstrap["registries"]) == 1 and reg["role"] == "control"
            and value["registry_id"] == reg["registry_id"] == bootstrap["control_authority"]["registry_id"]
            and value["origin"] == reg["origin"] == signatures.origin(value["origin"])
            and value["origin"].startswith("https://")
            and value["authority_id"] == bootstrap["control_authority"]["authority_id"]
            and value["installation_id"] == bootstrap["installation_id"]
            and value["state_volume_id"] == bootstrap["state"]["state_volume_id"],
            "station-binding-conflict", "Independent station expectation differs from installation")
    initial = bootstrap["initialization"]
    require(initial["expected_host_uuid"] in (None, value["host_id"])
            and initial["expected_fingerprint"] in (None, value["fingerprint"])
            and value["station_key_id"] != value["fingerprint"],
            "station-binding-conflict", "Independent station expectation differs from Host identity")
    return value


def load(bootstrap):
    # Walk and validate all ancestors using retained descriptors. The service
    # cannot substitute the protected file even through a writable parent.
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in PATH.split("/")[1:-1]:
            info = os.fstat(fd)
            require(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid) == (0, 0)
                    and not info.st_mode & 0o022, "station-binding-owner", "Unsafe expectation parent")
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        require((info.st_uid, info.st_gid) == (0, 0) and not info.st_mode & 0o022,
                "station-binding-owner", "Unsafe expectation directory")
        return validate(decode(read_at(fd, PATH.rsplit("/", 1)[1], 0, 0, 0o444)), bootstrap)
    finally:
        os.close(fd)
