import uuid

import pytest

from zog.host_install.state_contract import StateError
from zog.host_discover.credential_delivery import managed_binding
from zog.host_identify import credential_delivery


def fixture():
    host = str(uuid.uuid4())
    installation = str(uuid.uuid4())
    state = str(uuid.uuid4())
    saved = {
        "installation_id": installation,
        "state_volume_id": state,
        "fingerprint": "a" * 64,
        "registries": {
            "primary": {
                "origin": "https://station.example.test",
                "role": "control",
                "host_id": host,
                "public_key": "public-key-material",
                "previous": {"epoch": 3, "checkpoint": str(uuid.uuid4())},
                "pending": None,
            },
        },
    }
    bootstrap = {
        "registries": [
            {
                "registry_id": "primary",
                "origin": "https://station.example.test",
                "role": "control",
            },
            {
                "registry_id": "observer",
                "origin": "https://observer.example.test",
                "role": "observation",
            },
        ],
    }
    return saved, bootstrap


def test_exact_managed_binding_is_nonsecret_and_protocol_valid():
    saved, bootstrap = fixture()
    value = managed_binding(
        saved,
        bootstrap,
        "primary",
        consumer="certify-manage",
        purpose="issuer-cloudflare-dns01",
        credential_id="cloudflare-station",
    )
    assert value == credential_delivery.binding(value)
    assert value["host_id"] == saved["registries"]["primary"]["host_id"]
    assert value["host_fingerprint"] == saved["fingerprint"]
    assert value["installation_id"] == saved["installation_id"]
    assert value["state_volume_id"] == saved["state_volume_id"]
    assert value["registry_id"] == "primary"
    encoded = repr(value).lower()
    assert "secret" not in encoded
    assert "password" not in encoded
    assert "token" not in encoded


def test_observation_registry_cannot_be_credential_authority():
    saved, bootstrap = fixture()
    saved["registries"]["observer"] = {
        "origin": "https://observer.example.test",
        "role": "observation",
        "host_id": str(uuid.uuid4()),
        "public_key": "observer-key",
        "previous": None,
        "pending": None,
    }
    with pytest.raises(StateError, match="control registry"):
        managed_binding(
            saved,
            bootstrap,
            "observer",
            consumer="certify-manage",
            purpose="issuer-cloudflare-dns01",
            credential_id="cloudflare-station",
        )


@pytest.mark.parametrize("field", ["host_id", "public_key", "pending"])
def test_incomplete_or_transitioning_control_registry_is_rejected(field):
    saved, bootstrap = fixture()
    if field == "pending":
        saved["registries"]["primary"][field] = {"challenge": str(uuid.uuid4())}
    else:
        saved["registries"]["primary"][field] = None
    with pytest.raises(StateError, match="incomplete"):
        managed_binding(
            saved,
            bootstrap,
            "primary",
            consumer="station-access",
            purpose="administrator-bootstrap",
            credential_id="station-admin",
        )


def test_binding_does_not_authorize_arbitrary_bad_purpose():
    saved, bootstrap = fixture()
    with pytest.raises(StateError, match="invalid"):
        managed_binding(
            saved,
            bootstrap,
            "primary",
            consumer="station-access",
            purpose="../admin-password",
            credential_id="station-admin",
        )
