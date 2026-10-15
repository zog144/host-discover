"""Authenticated, signed command-center certificate-assignment retrieval.

This module transports authority only. It never creates certify-manage policy,
reads provider secrets, changes DNS, launches an issuer, or installs TLS keys.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import stat
import time
import urllib.request
from urllib.parse import urlsplit
import uuid

from cryptography.exceptions import InvalidSignature
from zog.host_identify import signatures, storage


REQUEST_SCHEMA = "zog-host-certificate-assignment-request-v1"
RESPONSE_SCHEMA = "zog-host-certificate-assignment-response-v1"
ASSIGNMENT_SCHEMA = "zog-certificate-assignment-v1"
ENVELOPE_SCHEMA = "zog-certificate-assignment-envelope-v1"
STATE_SCHEMA = "zog-host-certificate-assignment-state-v1"

_STATE_NAME = "certificate-assignment.json"
_LOCK_NAME = "certificate-assignment.lock"
_MANAGED_PENDING = "certificate-assignment.pending"
_MANAGED_NEXT = "certificate-assignment.next"

_MAX_RESPONSE = 16384
_MAX_STATE = 32768
_MAX_OPERATIONS = 128
_MAX_AUTHORITY_LIFETIME = 31 * 24 * 60 * 60
_CLOCK_SKEW = 300

_ID = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_OPERATION = re.compile(r"[0-9a-f]{32}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_EMAIL = re.compile(
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+"
    r"(?:\.[A-Za-z0-9-]+)+\Z"
)


class AssignmentError(ValueError):
    """Fail-closed assignment protocol or retained-state error."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _assignment_bytes(value: dict) -> bytes:
    return b"zog-certificate-assignment-v1\0" + _canonical(value)


def _digest(value: dict) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _uuid(value: object, code: str) -> str:
    try:
        parsed = str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise AssignmentError(code) from exc
    if value != parsed:
        raise AssignmentError(code)
    return parsed


def _hostname(value: object, *, wildcard: bool = False) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 253
        or value != value.lower()
    ):
        raise AssignmentError("invalid-hostname")
    raw = value[2:] if wildcard and value.startswith("*.") else value
    if (raw == value and "*" in value) or raw.endswith(".") or "." not in raw:
        raise AssignmentError("invalid-hostname")
    if any(not _LABEL.fullmatch(part) for part in raw.split(".")):
        raise AssignmentError("invalid-hostname")
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        raise AssignmentError("ip-address-not-allowed")
    return value


def _https_directory(value: object) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise AssignmentError("invalid-acme-directory")
    try:
        parsed = urlsplit(value)
        valid = (
            parsed.scheme == "https"
            and parsed.hostname is not None
            and parsed.hostname == parsed.hostname.lower()
            and parsed.username is None
            and parsed.password is None
            and parsed.port in (None, 443)
            and parsed.path.startswith("/")
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        valid = False
    if not valid:
        raise AssignmentError("invalid-acme-directory")
    return value


def validate_settings(configuration: dict) -> dict | None:
    """Validate the optional separately pinned command-center receipt key."""
    settings = configuration.get("certificate_assignment")
    if settings is None:
        return None
    if (
        not isinstance(settings, dict)
        or set(settings) != {"authority_public_key"}
        or not isinstance(settings["authority_public_key"], str)
    ):
        raise AssignmentError("invalid-certificate-assignment-settings")
    try:
        key = signatures.public_key(settings["authority_public_key"])
    except (TypeError, ValueError) as exc:
        raise AssignmentError("invalid-certificate-assignment-authority-key") from exc
    return {
        "authority_public_key": settings["authority_public_key"],
        "authority_key_id": signatures.fingerprint(key),
    }


def validate_assignment(
    value: object,
    *,
    expected_host: str,
    expected_installation: str | None,
    now: float | None = None,
) -> dict:
    """Validate one signed authority payload without turning it into issuer policy."""
    now = time.time() if now is None else float(now)
    required = {
        "schema",
        "authority_origin",
        "host_id",
        "installation_id",
        "operation_id",
        "revision",
        "status",
        "approved_at",
        "revoked_at",
        "expires_at",
        "certificate_id",
        "hostnames",
        "contact_email",
        "acme_directory",
        "challenge",
        "dns_mode",
        "dns_zone",
        "credential_id",
        "credential_revision",
        "consumer",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise AssignmentError("invalid-assignment-schema")
    if value["schema"] != ASSIGNMENT_SCHEMA:
        raise AssignmentError("unsupported-assignment-schema")
    if value["authority_origin"] != "command-center":
        raise AssignmentError("conflicting-authority-origin")

    host = _uuid(value["host_id"], "invalid-assignment-host")
    if host != expected_host:
        raise AssignmentError("assignment-host-mismatch")

    installation = value["installation_id"]
    if expected_installation is None:
        if installation is not None:
            raise AssignmentError("assignment-installation-mismatch")
    elif _uuid(installation, "assignment-installation-mismatch") != expected_installation:
        raise AssignmentError("assignment-installation-mismatch")

    _uuid(value["operation_id"], "invalid-assignment-operation")
    if (
        type(value["revision"]) is not int
        or not 1 <= value["revision"] <= 2**53 - 1
    ):
        raise AssignmentError("invalid-assignment-revision")
    if value["status"] not in {"approved", "revoked"}:
        raise AssignmentError("invalid-assignment-status")

    approved_at = value["approved_at"]
    expires_at = value["expires_at"]
    revoked_at = value["revoked_at"]
    if (
        type(approved_at) is not int
        or type(expires_at) is not int
        or approved_at <= 0
        or not approved_at < expires_at
        or expires_at - approved_at > _MAX_AUTHORITY_LIFETIME
        or approved_at > now + _CLOCK_SKEW
    ):
        raise AssignmentError("invalid-assignment-expiry")
    if value["status"] == "approved":
        if revoked_at is not None:
            raise AssignmentError("invalid-assignment-revocation")
    elif (
        type(revoked_at) is not int
        or revoked_at < approved_at
        or revoked_at > now + _CLOCK_SKEW
    ):
        raise AssignmentError("invalid-assignment-revocation")

    if (
        not isinstance(value["certificate_id"], str)
        or not _ID.fullmatch(value["certificate_id"])
    ):
        raise AssignmentError("invalid-certificate-id")

    challenge = value["challenge"]
    if challenge not in {"http-01", "dns-01"}:
        raise AssignmentError("invalid-assignment-challenge")
    names = value["hostnames"]
    if not isinstance(names, list) or not 1 <= len(names) <= 20:
        raise AssignmentError("invalid-assignment-hostnames")
    parsed_names = [
        _hostname(name, wildcard=challenge == "dns-01") for name in names
    ]
    if len(set(parsed_names)) != len(parsed_names) or parsed_names != sorted(parsed_names):
        raise AssignmentError("noncanonical-assignment-hostnames")

    email = value["contact_email"]
    if not isinstance(email, str) or len(email) > 254 or not _EMAIL.fullmatch(email):
        raise AssignmentError("invalid-assignment-contact")
    _https_directory(value["acme_directory"])

    consumer = value["consumer"]
    if not isinstance(consumer, str) or not _ID.fullmatch(consumer):
        raise AssignmentError("invalid-assignment-consumer")

    dns_mode = value["dns_mode"]
    zone = value["dns_zone"]
    credential = value["credential_id"]
    credential_revision = value["credential_revision"]
    if challenge == "http-01":
        if any(item is not None for item in (
            dns_mode, zone, credential, credential_revision
        )):
            raise AssignmentError("unexpected-dns-binding")
    else:
        if dns_mode not in {"local-cloudflare", "command-center-broker"}:
            raise AssignmentError("invalid-dns-mode")
        zone = _hostname(zone)
        bare_names = [
            name[2:] if name.startswith("*.") else name for name in parsed_names
        ]
        if any(name != zone and not name.endswith("." + zone) for name in bare_names):
            raise AssignmentError("hostname-outside-assigned-zone")
        if dns_mode == "local-cloudflare":
            if (
                not isinstance(credential, str)
                or not _ID.fullmatch(credential)
                or type(credential_revision) is not int
                or not 1 <= credential_revision <= 2**53 - 1
            ):
                raise AssignmentError("invalid-credential-binding")
        elif credential is not None or credential_revision is not None:
            raise AssignmentError("broker-must-not-carry-credential-binding")

    return value


def validate_envelope(
    value: object,
    authority_key,
    *,
    expected_host: str,
    expected_installation: str | None,
    now: float | None = None,
) -> dict:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "key_id", "assignment", "signature"}
        or value["schema"] != ENVELOPE_SCHEMA
    ):
        raise AssignmentError("invalid-assignment-envelope")
    key_id = signatures.fingerprint(authority_key)
    if value["key_id"] != key_id:
        raise AssignmentError("assignment-authority-key-mismatch")
    assignment = validate_assignment(
        value["assignment"],
        expected_host=expected_host,
        expected_installation=expected_installation,
        now=now,
    )
    try:
        signature = base64.b64decode(value["signature"], validate=True)
    except (ValueError, TypeError) as exc:
        raise AssignmentError("invalid-assignment-signature") from exc
    if len(signature) != 64 or base64.b64encode(signature).decode() != value["signature"]:
        raise AssignmentError("invalid-assignment-signature")
    try:
        authority_key.verify(signature, _assignment_bytes(assignment))
    except InvalidSignature as exc:
        raise AssignmentError("invalid-assignment-signature") from exc
    return assignment


def make_request(
    host_id: str,
    state: dict | None,
    *,
    installation_id: str | None = None,
    managed_session: str | None = None,
) -> dict:
    return {
        "schema": REQUEST_SCHEMA,
        "host_id": host_id,
        "installation_id": installation_id,
        "known_revision": state["revision"] if state else 0,
        "known_operation_id": state["operation_id"] if state else None,
        "managed_session": managed_session,
    }


def validate_response(
    value: object,
    *,
    known_revision: int,
    expected_host: str,
) -> dict:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "host_id", "state", "revision", "envelope"}
        or value["schema"] != RESPONSE_SCHEMA
        or value["host_id"] != expected_host
    ):
        raise AssignmentError("invalid-assignment-response")
    state = value["state"]
    revision = value["revision"]
    if type(revision) is not int or not 0 <= revision <= 2**53 - 1:
        raise AssignmentError("invalid-assignment-response")
    if state == "unassigned":
        if known_revision != 0 or revision != 0 or value["envelope"] is not None:
            raise AssignmentError("invalid-unassigned-response")
    elif state == "unchanged":
        if (
            known_revision < 1
            or revision != known_revision
            or value["envelope"] is not None
        ):
            raise AssignmentError("invalid-unchanged-response")
    elif state == "receipt":
        if not isinstance(value["envelope"], dict) or revision < 1:
            raise AssignmentError("invalid-receipt-response")
    else:
        raise AssignmentError("invalid-assignment-response-state")
    return value


def _validate_state(
    value: object,
    authority_key,
    *,
    expected_host: str,
    expected_installation: str | None,
    now: float | None = None,
) -> dict:
    if (
        not isinstance(value, dict)
        or set(value) != {
            "schema", "host_id", "installation_id", "revision",
            "operation_id", "assignment_sha256", "operations", "envelope",
        }
        or value["schema"] != STATE_SCHEMA
        or value["host_id"] != expected_host
        or value["installation_id"] != expected_installation
        or type(value["revision"]) is not int
        or value["revision"] < 1
        or not isinstance(value["operation_id"], str)
        or not isinstance(value["assignment_sha256"], str)
        or not _SHA256.fullmatch(value["assignment_sha256"])
        or not isinstance(value["operations"], list)
        or not 1 <= len(value["operations"]) <= _MAX_OPERATIONS
    ):
        raise AssignmentError("invalid-retained-assignment-state")
    assignment = validate_envelope(
        value["envelope"],
        authority_key,
        expected_host=expected_host,
        expected_installation=expected_installation,
        now=now,
    )
    digest = _digest(assignment)
    if (
        assignment["revision"] != value["revision"]
        or assignment["operation_id"] != value["operation_id"]
        or digest != value["assignment_sha256"]
    ):
        raise AssignmentError("retained-assignment-state-mismatch")
    seen = set()
    for row in value["operations"]:
        if (
            not isinstance(row, dict)
            or set(row) != {"operation_id", "sha256"}
            or not isinstance(row["operation_id"], str)
            or not isinstance(row["sha256"], str)
            or not _SHA256.fullmatch(row["sha256"])
            or row["operation_id"] in seen
        ):
            raise AssignmentError("invalid-assignment-operation-history")
        _uuid(row["operation_id"], "invalid-assignment-operation-history")
        seen.add(row["operation_id"])
    _uuid(value["operation_id"], "invalid-retained-assignment-state")
    if value["operation_id"] not in seen:
        raise AssignmentError("missing-current-assignment-operation")
    return value


def _next_state(
    previous: dict | None,
    envelope: dict,
    authority_key,
    *,
    expected_host: str,
    expected_installation: str | None,
    now: float | None = None,
) -> tuple[dict, bool]:
    assignment = validate_envelope(
        envelope,
        authority_key,
        expected_host=expected_host,
        expected_installation=expected_installation,
        now=now,
    )
    digest = _digest(assignment)
    revision = assignment["revision"]
    operation_id = assignment["operation_id"]
    if previous:
        if revision < previous["revision"]:
            raise AssignmentError("stale-assignment-revision")
        if revision == previous["revision"]:
            if (
                digest != previous["assignment_sha256"]
                or operation_id != previous["operation_id"]
            ):
                raise AssignmentError("conflicting-assignment-revision")
            return previous, False
        matches = {
            row["operation_id"]: row["sha256"] for row in previous["operations"]
        }
        if operation_id in matches:
            raise AssignmentError(
                "conflicting-assignment-operation"
                if matches[operation_id] != digest
                else "reused-assignment-operation"
            )
        if len(previous["operations"]) >= _MAX_OPERATIONS:
            raise AssignmentError("assignment-operation-history-full")
        operations = list(previous["operations"])
    else:
        operations = []
    operations.append({"operation_id": operation_id, "sha256": digest})
    result = {
        "schema": STATE_SCHEMA,
        "host_id": expected_host,
        "installation_id": expected_installation,
        "revision": revision,
        "operation_id": operation_id,
        "assignment_sha256": digest,
        "operations": operations,
        "envelope": envelope,
    }
    raw = _canonical(result)
    if len(raw) > _MAX_STATE:
        raise AssignmentError("assignment-state-too-large")
    return result, True


def _legacy_state(
    root: Path,
    authority_key,
    *,
    expected_host: str,
    now: float | None = None,
) -> dict | None:
    path = root / _STATE_NAME
    if not path.exists():
        return None
    value = json.loads(storage.read_owned(path, 0o600))
    return _validate_state(
        value,
        authority_key,
        expected_host=expected_host,
        expected_installation=None,
        now=now,
    )


def _binding(configuration: dict, key) -> str | None:
    root = storage.directory(configuration["identity_directory"])
    path = root / "binding.json"
    if not path.exists():
        return None
    value = json.loads(storage.read_owned(path, 0o600))
    if (
        not isinstance(value, dict)
        or set(value) != {"host_id", "fingerprint"}
        or value["fingerprint"] != signatures.fingerprint(key.public_key())
    ):
        raise AssignmentError("certificate-assignment-binding-mismatch")
    try:
        host = str(uuid.UUID(value["host_id"]))
    except (ValueError, TypeError, AttributeError) as exc:
        raise AssignmentError("certificate-assignment-binding-mismatch") from exc
    if value["host_id"] != host:
        raise AssignmentError("certificate-assignment-binding-mismatch")
    return host


def _legacy_commit(
    root: Path,
    envelope: dict,
    authority_key,
    *,
    expected_host: str,
    now: float | None = None,
) -> tuple[dict, bool]:
    lock = root / _LOCK_NAME
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        storage.read_owned(lock, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        previous = _legacy_state(
            root, authority_key, expected_host=expected_host, now=now
        )
        result, changed = _next_state(
            previous,
            envelope,
            authority_key,
            expected_host=expected_host,
            expected_installation=None,
            now=now,
        )
        if changed:
            storage.atomic(root / _STATE_NAME, _canonical(result), 0o600)
        return result, changed
    finally:
        os.close(fd)


def active_assignment(configuration: dict, *, now: float | None = None) -> dict | None:
    """Return only a currently effective signed assignment; never policy."""
    settings = validate_settings(configuration)
    if settings is None:
        return None
    from .daemon import identity_key
    key = identity_key(configuration)
    host = _binding(configuration, key)
    if host is None:
        return None
    authority_key = signatures.public_key(settings["authority_public_key"])
    if signatures.fingerprint(key.public_key()) == settings["authority_key_id"]:
        raise AssignmentError("assignment-authority-not-distinct")
    state = _legacy_state(
        storage.directory(configuration["identity_directory"]),
        authority_key,
        expected_host=host,
        now=now,
    )
    if state is None:
        return None
    assignment = state["envelope"]["assignment"]
    moment = time.time() if now is None else float(now)
    if (
        assignment["status"] != "approved"
        or assignment["approved_at"] > moment
        or assignment["expires_at"] <= moment
    ):
        return None
    return dict(assignment)


def inspect_assignment(configuration: dict, *, now: float | None = None) -> dict:
    settings = validate_settings(configuration)
    if settings is None:
        return {"status": "disabled", "revision": 0}
    from .daemon import identity_key
    key = identity_key(configuration)
    host = _binding(configuration, key)
    if host is None:
        return {"status": "unbound", "revision": 0}
    authority_key = signatures.public_key(settings["authority_public_key"])
    if signatures.fingerprint(key.public_key()) == settings["authority_key_id"]:
        raise AssignmentError("assignment-authority-not-distinct")
    state = _legacy_state(
        storage.directory(configuration["identity_directory"]),
        authority_key,
        expected_host=host,
        now=now,
    )
    if state is None:
        return {"status": "unassigned", "revision": 0}
    assignment = state["envelope"]["assignment"]
    moment = time.time() if now is None else float(now)
    status = assignment["status"]
    if status == "approved" and assignment["approved_at"] > moment:
        status = "not-yet-valid"
    elif status == "approved" and assignment["expires_at"] <= moment:
        status = "expired"
    return {
        "status": status,
        "revision": assignment["revision"],
        "operation_id": assignment["operation_id"],
        "expires_at": assignment["expires_at"],
        "certificate_id": assignment["certificate_id"],
        "hostnames": list(assignment["hostnames"]),
        "consumer": assignment["consumer"],
        "authority_key_id": settings["authority_key_id"],
    }


def retrieve(configuration: dict, *, now: float | None = None) -> dict:
    """Fetch one bounded central assignment using the already approved host key."""
    settings = validate_settings(configuration)
    if settings is None:
        return {"status": "disabled", "revision": 0}

    from .daemon import NoRedirect, identity_key
    key = identity_key(configuration)
    host = _binding(configuration, key)
    if host is None:
        return {"status": "unbound", "revision": 0}

    root = storage.directory(configuration["identity_directory"])
    authority_key = signatures.public_key(settings["authority_public_key"])
    if signatures.fingerprint(key.public_key()) == settings["authority_key_id"]:
        raise AssignmentError("assignment-authority-not-distinct")
    previous = _legacy_state(
        root, authority_key, expected_host=host, now=now
    )
    payload = make_request(host, previous)
    body = _canonical(payload)
    url = (
        configuration["server"].rstrip("/")
        + "/api/hosts/"
        + host
        + "/certificate-assignment/"
    )
    prepared = signatures.sign(url, body, key, host)
    context = ssl.create_default_context(cafile=configuration.get("ca_file") or None)
    opener = urllib.request.build_opener(
        NoRedirect(),
        urllib.request.HTTPSHandler(context=context),
        urllib.request.ProxyHandler({}),
    )
    request = urllib.request.Request(
        prepared.url,
        data=prepared.body,
        headers=dict(prepared.headers),
        method="POST",
    )
    with opener.open(request, timeout=10) as response:
        if response.status != 200:
            raise AssignmentError("unexpected-certificate-assignment-status")
        raw = response.read(_MAX_RESPONSE + 1)
        if len(raw) > _MAX_RESPONSE:
            raise AssignmentError("oversize-certificate-assignment-response")
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise AssignmentError("invalid-certificate-assignment-json") from exc
    response = validate_response(
        value,
        known_revision=previous["revision"] if previous else 0,
        expected_host=host,
    )
    if response["state"] == "unassigned":
        return {"status": "unassigned", "revision": 0}
    if response["state"] == "unchanged":
        current = inspect_assignment(configuration, now=now)
        return {"status": current["status"], "revision": current["revision"]}
    assignment = validate_envelope(
        response["envelope"],
        authority_key,
        expected_host=host,
        expected_installation=None,
        now=now,
    )
    if response["revision"] != assignment["revision"]:
        raise AssignmentError("assignment-response-revision-mismatch")
    state, changed = _legacy_commit(
        root,
        response["envelope"],
        authority_key,
        expected_host=host,
        now=now,
    )
    latest = state["envelope"]["assignment"]
    moment = time.time() if now is None else float(now)
    status = latest["status"]
    if status == "approved" and latest["approved_at"] > moment:
        status = "not-yet-valid"
    elif status == "approved" and latest["expires_at"] <= moment:
        status = "expired"
    return {
        "status": status,
        "revision": latest["revision"],
        "changed": changed,
    }


def managed_read_state(
    directory_fd: int,
    authority_key,
    *,
    expected_host: str,
    expected_installation: str,
    now: float | None = None,
) -> dict | None:
    """Read separately persisted assignment state under an already anchored fd."""
    names = set(os.listdir(directory_fd))
    if _MANAGED_PENDING in names or _MANAGED_NEXT in names:
        raise AssignmentError("managed-assignment-write-incomplete")
    if _STATE_NAME not in names:
        return None
    fd = os.open(
        _STATE_NAME,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=directory_fd,
    )
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size > _MAX_STATE
        ):
            raise AssignmentError("unsafe-managed-assignment-state")
        raw = os.read(fd, _MAX_STATE + 1)
    finally:
        os.close(fd)
    if len(raw) > _MAX_STATE:
        raise AssignmentError("assignment-state-too-large")
    return _validate_state(
        json.loads(raw),
        authority_key,
        expected_host=expected_host,
        expected_installation=expected_installation,
        now=now,
    )


def managed_commit(
    directory_fd: int,
    envelope: dict,
    authority_key,
    *,
    expected_host: str,
    expected_installation: str,
    now: float | None = None,
) -> tuple[dict, bool]:
    """Durably publish managed assignment state while the caller owns its lock."""
    previous = managed_read_state(
        directory_fd,
        authority_key,
        expected_host=expected_host,
        expected_installation=expected_installation,
        now=now,
    )
    result, changed = _next_state(
        previous,
        envelope,
        authority_key,
        expected_host=expected_host,
        expected_installation=expected_installation,
        now=now,
    )
    if not changed:
        return result, False
    raw = _canonical(result)
    fd = os.open(
        _MANAGED_PENDING,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=directory_fd,
    )
    try:
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise AssignmentError("managed-assignment-short-write")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory_fd)
    os.link(
        _MANAGED_PENDING,
        _MANAGED_NEXT,
        src_dir_fd=directory_fd,
        dst_dir_fd=directory_fd,
        follow_symlinks=False,
    )
    os.replace(
        _MANAGED_NEXT,
        _STATE_NAME,
        src_dir_fd=directory_fd,
        dst_dir_fd=directory_fd,
    )
    os.fsync(directory_fd)
    os.unlink(_MANAGED_PENDING, dir_fd=directory_fd)
    os.fsync(directory_fd)
    return result, True
