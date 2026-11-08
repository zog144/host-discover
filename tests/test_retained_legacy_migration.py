"""Explicit retained migration preserves the existing beacon identity without fallback."""
import json
import uuid
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import URLError

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from zog.host_discover import daemon, destinations
from zog.host_identify.signatures import fingerprint


def configuration():
    key = Ed25519PrivateKey.generate()
    return key, {
        "server": "https://registry.example.invalid",
        "host_id": str(uuid.uuid4()),
        "provider": "generic",
        "identity_directory": "/state/host-discover/identity",
        "credential_directory": "/var/lib/host-discover/credentials",
        "identity_mode": "existing-legacy-migration",
        "retained_fingerprint": fingerprint(key.public_key()),
        "archive_issuer": "existing-issuer",
        "archive_audience": "existing-audience",
    }


def test_migrated_key_selection_preserves_existing_enrollment_and_is_repeatable():
    key, config = configuration()
    saved = {"host_id": config["host_id"], "fingerprint": config["retained_fingerprint"]}
    with patch("zog.host_identify.retained_legacy.load_retained_legacy_fd",
               return_value=(key, saved)) as retained, \
         patch("zog.host_identify.storage.load_key", side_effect=AssertionError("must not initialize")), \
         patch("zog.host_identify.storage.load_existing_key", side_effect=AssertionError("must not fallback")):
        for _ in range(3):
            got = daemon.identity_key(config, identity_fd=11, completion_fd=12)
            assert fingerprint(got.public_key()) == saved["fingerprint"]
        assert retained.call_count == 3
        assert retained.call_args.kwargs["expected_host_uuid"] == config["host_id"]
        assert retained.call_args.kwargs["expected_registry_origin"] == config["server"]


def test_offline_control_registry_does_not_invalidate_or_reenroll():
    key, config = configuration()
    saved = {"host_id": config["host_id"], "fingerprint": config["retained_fingerprint"]}
    attempted = []
    def sign(url, body, key, host_id):
        attempted.append((url, host_id))
        return SimpleNamespace(url=url, body=body, headers={})
    opener = SimpleNamespace(open=lambda *a, **k: (_ for _ in ()).throw(URLError("offline")))
    with patch("zog.host_identify.retained_legacy.load_retained_legacy_fd", return_value=(key,saved)), \
         patch("zog.host_identify.storage.purge_expired"), \
         patch("zog.host_identify.storage.clear_credentials", side_effect=AssertionError("must preserve credentials")), \
         patch("zog.host_discover.daemon.signatures", create=True) as unused, \
         patch("zog.host_identify.signatures.sign", side_effect=sign), \
         patch("zog.host_discover.daemon.urllib.request.build_opener", return_value=opener), \
         patch("zog.host_discover.roles.Controller") as controller:
        with pytest.raises(URLError):
            daemon.announce(config, {"version":1}, identity_fd=11, completion_fd=12)
    assert attempted == [(config["server"] + "/api/hosts/" + config["host_id"] + "/heartbeat/", config["host_id"])]


def test_missing_or_conflicting_receipts_never_load_or_generate():
    key, config = configuration()
    with patch("zog.host_identify.storage.load_key", side_effect=AssertionError("no generation")):
        for kwargs in ({}, {"identity_fd":3}, {"completion_fd":4}):
            with pytest.raises(daemon.IdentityUnavailableError):
                daemon.identity_key(config, **kwargs)
        with patch("zog.host_identify.retained_legacy.load_retained_legacy_fd", side_effect=PermissionError("foreign")):
            with pytest.raises(daemon.IdentityUnavailableError):
                daemon.identity_key(config, identity_fd=3, completion_fd=4)


def test_state_path_requires_explicit_selection_and_old_legacy_is_unchanged():
    key, config = configuration()
    with pytest.raises(ValueError):
        daemon.validate_configuration(dict(config, identity_mode="existing-only"))
    with pytest.raises(ValueError):
        daemon.validate_configuration(dict(config, identity_directory="/state/other/identity"))
    with pytest.raises(ValueError):
        daemon.validate_configuration(dict(config, host_id=""))
    ordinary = dict(config, identity_directory="/var/lib/host-discover/identity",identity_mode="existing-only")
    daemon.validate_configuration(ordinary)
    with patch("zog.host_identify.storage.load_existing_key", return_value=key) as old:
        assert daemon.identity_key(ordinary) is key
        old.assert_called_once_with(ordinary["identity_directory"])


def test_retained_primary_destination_unchanged_and_secondary_denied():
    key, config = configuration()
    rows = {"version":1,"destinations":[
        {"id":"primary","label":"primary","server":config["server"],
         "enabled":True,"ca_certificate":"","revision":1},
        {"id":"secondary","label":"secondary","server":"https://second.example.invalid",
         "enabled":False,"ca_certificate":"","revision":1},
    ]}
    with patch("zog.host_identify.storage.read_owned",return_value=json.dumps(rows).encode()), \
         patch("zog.host_identify.storage.atomic",side_effect=AssertionError("must not write")), \
         patch("zog.host_identify.storage.directory",side_effect=AssertionError("must not create")):
        selected=destinations.configurations(config,"/var/lib/host-discover/beacon-destinations.json")
    assert selected==[(True,config)]
    rows["destinations"][1]["enabled"]=True
    with patch("zog.host_identify.storage.read_owned",return_value=json.dumps(rows).encode()):
        with pytest.raises(PermissionError):
            destinations.configurations(config,"/var/lib/host-discover/beacon-destinations.json")
