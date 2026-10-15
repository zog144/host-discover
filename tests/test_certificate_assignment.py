import base64
import json
import time
import uuid
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from zog.host_discover import certificate_assignment as assignment
from zog.host_discover.certificate_assignment import (
    AssignmentError,
    active_assignment,
    inspect_assignment,
    retrieve,
)
from zog.host_identify import signatures, storage


class Response:
    def __init__(self, value, status=200):
        self.value = value
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self, maximum):
        raw = json.dumps(self.value, separators=(",", ":")).encode()
        return raw[:maximum]


@pytest.fixture
def authority():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def configuration(tmp_path, authority):
    identity = tmp_path / "identity"
    credentials = tmp_path / "credentials"
    identity.mkdir(mode=0o700)
    credentials.mkdir(mode=0o750)
    key = storage.load_key(identity)
    host = str(uuid.uuid4())
    storage.atomic(
        identity / "binding.json",
        json.dumps({
            "host_id": host,
            "fingerprint": signatures.fingerprint(key.public_key()),
        }).encode(),
    )
    return {
        "server": "https://registry.example.test",
        "identity_directory": str(identity),
        "credential_directory": str(credentials),
        "provider": "generic",
        "certificate_assignment": {
            "authority_public_key": signatures.public_text(authority.public_key()),
        },
    }


def payload(host, *, now, revision=1, operation_id=None, status="approved"):
    return {
        "schema": assignment.ASSIGNMENT_SCHEMA,
        "authority_origin": "command-center",
        "host_id": host,
        "installation_id": None,
        "operation_id": operation_id or str(uuid.uuid4()),
        "revision": revision,
        "status": status,
        "approved_at": now - 60,
        "revoked_at": now - 1 if status == "revoked" else None,
        "expires_at": now + 3600,
        "certificate_id": "station-https",
        "hostnames": ["station.hosts.example.test"],
        "contact_email": "acme@example.test",
        "acme_directory": "https://acme.example.test/directory",
        "challenge": "dns-01",
        "dns_mode": "local-cloudflare",
        "dns_zone": "hosts.example.test",
        "credential_id": "cloudflare-station",
        "credential_revision": 3,
        "consumer": "station-access",
    }


def envelope(authority, value):
    signature = authority.sign(assignment._assignment_bytes(value))
    return {
        "schema": assignment.ENVELOPE_SCHEMA,
        "key_id": signatures.fingerprint(authority.public_key()),
        "assignment": value,
        "signature": base64.b64encode(signature).decode(),
    }


def response(host, env):
    return {
        "schema": assignment.RESPONSE_SCHEMA,
        "host_id": host,
        "state": "receipt",
        "revision": env["assignment"]["revision"],
        "envelope": env,
    }


def host_id(configuration):
    value = json.loads(
        (Path(configuration["identity_directory"]) / "binding.json").read_text()
    )
    return value["host_id"]


def test_signed_retrieval_needs_no_initial_fqdn_and_uses_separate_endpoint(
        configuration, authority):
    now = int(time.time())
    host = host_id(configuration)
    env = envelope(authority, payload(host, now=now))
    sent = []

    def open_request(request, **kwargs):
        sent.append(request)
        return Response(response(host, env))

    with patch("urllib.request.OpenerDirector.open", side_effect=open_request):
        result = retrieve(configuration, now=now)

    assert result == {"status": "approved", "revision": 1, "changed": True}
    assert len(sent) == 1
    request = sent[0]
    assert request.full_url == (
        f"https://registry.example.test/api/hosts/{host}/certificate-assignment/"
    )
    body = json.loads(request.data)
    assert body == {
        "schema": assignment.REQUEST_SCHEMA,
        "host_id": host,
        "installation_id": None,
        "known_revision": 0,
        "known_operation_id": None,
        "managed_session": None,
    }
    assert "hostname" not in body and "fqdn" not in body
    key = storage.load_key(configuration["identity_directory"])
    signatures.verify(
        request.full_url,
        "POST",
        dict(request.header_items()),
        request.data,
        key.public_key(),
        host,
    )
    assert active_assignment(configuration, now=now)["hostnames"] == [
        "station.hosts.example.test"
    ]


def test_unchanged_response_preserves_signed_receipt(configuration, authority):
    now = int(time.time())
    host = host_id(configuration)
    env = envelope(authority, payload(host, now=now))
    with patch(
        "urllib.request.OpenerDirector.open",
        return_value=Response(response(host, env)),
    ):
        retrieve(configuration, now=now)

    unchanged = {
        "schema": assignment.RESPONSE_SCHEMA,
        "host_id": host,
        "state": "unchanged",
        "revision": 1,
        "envelope": None,
    }
    with patch(
        "urllib.request.OpenerDirector.open",
        return_value=Response(unchanged),
    ) as opener:
        result = retrieve(configuration, now=now + 1)
    assert result == {"status": "approved", "revision": 1}
    request = opener.call_args.args[0]
    body = json.loads(request.data)
    assert body["known_revision"] == 1
    assert body["known_operation_id"] == env["assignment"]["operation_id"]


def test_unassigned_response_does_not_create_authority(configuration):
    host = host_id(configuration)
    value = {
        "schema": assignment.RESPONSE_SCHEMA,
        "host_id": host,
        "state": "unassigned",
        "revision": 0,
        "envelope": None,
    }
    with patch("urllib.request.OpenerDirector.open", return_value=Response(value)):
        assert retrieve(configuration)["status"] == "unassigned"
    assert inspect_assignment(configuration)["status"] == "unassigned"
    assert active_assignment(configuration) is None


def test_expired_signed_assignment_is_retained_but_not_active(
        configuration, authority):
    now = int(time.time())
    host = host_id(configuration)
    value = payload(host, now=now)
    value["approved_at"] = now - 7200
    value["expires_at"] = now - 1
    env = envelope(authority, value)
    with patch(
        "urllib.request.OpenerDirector.open",
        return_value=Response(response(host, env)),
    ):
        result = retrieve(configuration, now=now)
    assert result["status"] == "expired"
    assert inspect_assignment(configuration, now=now)["status"] == "expired"
    assert active_assignment(configuration, now=now) is None


def test_signed_revocation_supersedes_approved_assignment(
        configuration, authority):
    now = int(time.time())
    host = host_id(configuration)
    first = payload(host, now=now, revision=1)
    with patch(
        "urllib.request.OpenerDirector.open",
        return_value=Response(response(host, envelope(authority, first))),
    ):
        retrieve(configuration, now=now)

    revoked = payload(host, now=now, revision=2, status="revoked")
    with patch(
        "urllib.request.OpenerDirector.open",
        return_value=Response(response(host, envelope(authority, revoked))),
    ):
        result = retrieve(configuration, now=now)
    assert result["status"] == "revoked"
    assert result["revision"] == 2
    assert active_assignment(configuration, now=now) is None
    assert inspect_assignment(configuration, now=now)["status"] == "revoked"


def test_lower_revision_cannot_rollback_revocation(configuration, authority):
    now = int(time.time())
    host = host_id(configuration)
    high = payload(host, now=now, revision=3, status="revoked")
    with patch(
        "urllib.request.OpenerDirector.open",
        return_value=Response(response(host, envelope(authority, high))),
    ):
        retrieve(configuration, now=now)

    stale = payload(host, now=now, revision=2)
    with patch(
        "urllib.request.OpenerDirector.open",
        return_value=Response(response(host, envelope(authority, stale))),
    ):
        with pytest.raises(AssignmentError, match="stale-assignment-revision"):
            retrieve(configuration, now=now)
    assert inspect_assignment(configuration, now=now)["revision"] == 3


def test_same_revision_with_different_assignment_is_conflict(
        configuration, authority):
    now = int(time.time())
    host = host_id(configuration)
    operation = str(uuid.uuid4())
    first = payload(host, now=now, revision=1, operation_id=operation)
    with patch(
        "urllib.request.OpenerDirector.open",
        return_value=Response(response(host, envelope(authority, first))),
    ):
        retrieve(configuration, now=now)

    conflict = dict(first)
    conflict["hostnames"] = ["other.hosts.example.test"]
    with patch(
        "urllib.request.OpenerDirector.open",
        return_value=Response(response(host, envelope(authority, conflict))),
    ):
        with pytest.raises(AssignmentError, match="conflicting-assignment-revision"):
            retrieve(configuration, now=now)


def test_operation_id_cannot_be_reused_for_different_revision(
        configuration, authority):
    now = int(time.time())
    host = host_id(configuration)
    operation = str(uuid.uuid4())
    first = payload(host, now=now, revision=1, operation_id=operation)
    with patch(
        "urllib.request.OpenerDirector.open",
        return_value=Response(response(host, envelope(authority, first))),
    ):
        retrieve(configuration, now=now)

    reused = payload(host, now=now, revision=2, operation_id=operation)
    with patch(
        "urllib.request.OpenerDirector.open",
        return_value=Response(response(host, envelope(authority, reused))),
    ):
        with pytest.raises(AssignmentError, match="conflicting-assignment-operation"):
            retrieve(configuration, now=now)


@pytest.mark.parametrize("mutation", ["host", "origin", "signature"])
def test_mismatched_or_untrusted_receipt_is_rejected(
        configuration, authority, mutation):
    now = int(time.time())
    host = host_id(configuration)
    value = payload(host, now=now)
    env = envelope(authority, value)
    if mutation == "host":
        value = payload(str(uuid.uuid4()), now=now)
        env = envelope(authority, value)
    elif mutation == "origin":
        value["authority_origin"] = "local-station"
        env = envelope(authority, value)
    else:
        env["signature"] = base64.b64encode(b"x" * 64).decode()
    with patch(
        "urllib.request.OpenerDirector.open",
        return_value=Response(response(host, env)),
    ):
        with pytest.raises(AssignmentError):
            retrieve(configuration, now=now)
    assert inspect_assignment(configuration, now=now)["status"] == "unassigned"


@pytest.mark.parametrize(
    "failure",
    [
        URLError("offline"),
        HTTPError(
            "https://registry.example.test",
            403,
            "denied",
            {},
            None,
        ),
    ],
)
def test_transport_failure_does_not_implicitly_revoke_cached_authority(
        configuration, authority, failure):
    now = int(time.time())
    host = host_id(configuration)
    first = payload(host, now=now)
    with patch(
        "urllib.request.OpenerDirector.open",
        return_value=Response(response(host, envelope(authority, first))),
    ):
        retrieve(configuration, now=now)

    with patch("urllib.request.OpenerDirector.open", side_effect=failure):
        with pytest.raises(type(failure)):
            retrieve(configuration, now=now + 1)
    assert active_assignment(configuration, now=now + 1)["revision"] == 1


def test_changed_credential_binding_requires_new_revision(
        configuration, authority):
    now = int(time.time())
    host = host_id(configuration)
    first = payload(host, now=now, revision=1)
    with patch(
        "urllib.request.OpenerDirector.open",
        return_value=Response(response(host, envelope(authority, first))),
    ):
        retrieve(configuration, now=now)

    same_revision = dict(first)
    same_revision["credential_revision"] = 4
    with patch(
        "urllib.request.OpenerDirector.open",
        return_value=Response(response(host, envelope(authority, same_revision))),
    ):
        with pytest.raises(AssignmentError, match="conflicting-assignment-revision"):
            retrieve(configuration, now=now)

    next_revision = dict(same_revision)
    next_revision["revision"] = 2
    next_revision["operation_id"] = str(uuid.uuid4())
    with patch(
        "urllib.request.OpenerDirector.open",
        return_value=Response(response(host, envelope(authority, next_revision))),
    ):
        result = retrieve(configuration, now=now)
    assert result["revision"] == 2
    assert active_assignment(configuration, now=now)["credential_revision"] == 4


def test_wrong_zone_and_broker_credential_binding_are_rejected(
        configuration, authority):
    now = int(time.time())
    host = host_id(configuration)
    wrong_zone = payload(host, now=now)
    wrong_zone["dns_zone"] = "other.example.test"
    with pytest.raises(AssignmentError, match="hostname-outside-assigned-zone"):
        assignment.validate_envelope(
            envelope(authority, wrong_zone),
            authority.public_key(),
            expected_host=host,
            expected_installation=None,
            now=now,
        )

    broker = payload(host, now=now)
    broker["dns_mode"] = "command-center-broker"
    with pytest.raises(AssignmentError, match="broker-must-not-carry"):
        assignment.validate_envelope(
            envelope(authority, broker),
            authority.public_key(),
            expected_host=host,
            expected_installation=None,
            now=now,
        )


def test_settings_require_a_distinct_pinned_public_key(configuration):
    configuration["certificate_assignment"] = {}
    with pytest.raises(
        AssignmentError, match="invalid-certificate-assignment-settings"
    ):
        assignment.validate_settings(configuration)



def test_managed_assignment_state_binds_installation_and_blocks_partial_write(
        tmp_path, authority):
    directory = tmp_path / "control"
    directory.mkdir(mode=0o700)
    host = str(uuid.uuid4())
    installation = str(uuid.uuid4())
    now = int(time.time())
    value = payload(host, now=now)
    value["installation_id"] = installation
    env = envelope(authority, value)
    fd = __import__("os").open(
        directory,
        __import__("os").O_RDONLY | __import__("os").O_DIRECTORY,
    )
    try:
        state, changed = assignment.managed_commit(
            fd,
            env,
            authority.public_key(),
            expected_host=host,
            expected_installation=installation,
            now=now,
        )
        assert changed is True
        assert state["installation_id"] == installation
        again = assignment.managed_read_state(
            fd,
            authority.public_key(),
            expected_host=host,
            expected_installation=installation,
            now=now,
        )
        assert again["revision"] == 1
        with pytest.raises(AssignmentError, match="invalid-retained-assignment-state"):
            assignment.managed_read_state(
                fd,
                authority.public_key(),
                expected_host=host,
                expected_installation=str(uuid.uuid4()),
                now=now,
            )
        (directory / "certificate-assignment.pending").write_text("partial")
        (directory / "certificate-assignment.pending").chmod(0o600)
        with pytest.raises(AssignmentError, match="write-incomplete"):
            assignment.managed_read_state(
                fd,
                authority.public_key(),
                expected_host=host,
                expected_installation=installation,
                now=now,
            )
    finally:
        __import__("os").close(fd)
