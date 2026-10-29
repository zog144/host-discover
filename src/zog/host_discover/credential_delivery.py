"""Non-secret host-discover integration for HTTPS credential delivery v1.

host-discover may expose exact enrolled binding evidence to a protected owner,
but never receives or stores delivered secret bytes.  The common protocol and
secret state machine live in zog.host_identify.credential_delivery.
"""
from __future__ import annotations

from zog.host_install.state_contract import StateError, require
from zog.host_identify import credential_delivery


def managed_binding(
    saved: dict,
    bootstrap: dict,
    registry_id: str,
    *,
    consumer: str,
    purpose: str,
    credential_id: str,
) -> dict:
    """Return exact non-secret binding for a fully enrolled control registry.

    This helper is intentionally insufficient to authorize delivery.  The
    protected receiver must also verify independently trusted Credential
    Authority authorization and its own root-owned destination policy.
    """
    require(
        isinstance(saved, dict) and isinstance(bootstrap, dict),
        "credential-binding-invalid",
        "Managed binding state is invalid",
    )
    configured = {
        row["registry_id"]: row
        for row in bootstrap.get("registries", [])
        if isinstance(row, dict) and "registry_id" in row
    }
    require(
        registry_id in configured
        and configured[registry_id].get("role") == "control",
        "credential-registry-denied",
        "Credential delivery requires the configured control registry",
    )
    row = saved.get("registries", {}).get(registry_id)
    require(
        isinstance(row, dict)
        and row.get("role") == "control"
        and row.get("origin") == configured[registry_id].get("origin")
        and row.get("host_id") is not None
        and row.get("public_key") is not None
        and row.get("pending") is None,
        "credential-registry-unready",
        "Control registry enrollment/trust is incomplete",
    )
    value = {
        "host_id": row["host_id"],
        "host_fingerprint": saved.get("fingerprint"),
        "installation_id": saved.get("installation_id"),
        "state_volume_id": saved.get("state_volume_id"),
        "registry_id": registry_id,
        "consumer": consumer,
        "purpose": purpose,
        "credential_id": credential_id,
    }
    try:
        return credential_delivery.binding(value)
    except credential_delivery.CredentialProtocolError as exc:
        raise StateError(
            "credential-binding-invalid",
            "Credential delivery binding is invalid",
        ) from exc


def reject_heartbeat_delivery(response: dict) -> None:
    """Managed heartbeat/inspect is never the reusable secret transport."""
    require(
        isinstance(response, dict),
        "managed-heartbeat-response",
        "Heartbeat response must be a mapping",
    )
    require(
        "credential_delivery" not in response,
        "credential-delivery-channel-denied",
        "Credential delivery requires the protected root HTTPS receiver",
    )
