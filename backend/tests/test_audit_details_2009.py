"""#2009: the audit API returns an entry's recorded details, redacted."""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User

_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"


async def _admin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"a-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _entry(db: AsyncSession) -> AuditLog:
    row = AuditLog(
        action="appliance.upgrade_scheduled",
        resource_type="appliance",
        resource_id=str(uuid.uuid4()),
        resource_display="node-1",
        user_display_name="alice",
        auth_source="local",
        result="success",
        old_value={"api_key": "hunter2"},
        new_value={
            "direction": "backward",
            "schema_check": {"ok": False, "reason": "newer schema"},
            "desired_slot_image_url": "https://x/img",
            "registry_password": "s3cret",
            "note": f"token {_JWT}",
            "nested": [{"psk": "abcd"}],
        },
        changed_fields=["desired_appliance_version"],
    )
    db.add(row)
    await db.commit()
    return row


async def test_single_entry_returns_details_with_secrets_redacted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    row = await _entry(db_session)
    r = await client.get(f"/api/v1/audit/{row.id}", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    nv = body["new_value"]
    assert nv["direction"] == "backward"
    assert nv["schema_check"] == {"ok": False, "reason": "newer schema"}
    assert body["changed_fields"] == ["desired_appliance_version"]
    assert nv["registry_password"] == "[redacted]"
    assert nv["nested"][0]["psk"] == "[redacted]"
    assert body["old_value"]["api_key"] == "[redacted]"
    assert _JWT not in r.text and "s3cret" not in r.text and "hunter2" not in r.text


async def test_list_omits_details_unless_asked(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _admin(db_session)
    await _entry(db_session)
    plain = (await client.get("/api/v1/audit", headers=h)).json()["items"][0]
    assert plain["new_value"] is None
    full = (await client.get("/api/v1/audit?include_details=true", headers=h)).json()["items"][0]
    assert full["new_value"]["direction"] == "backward"
    assert full["new_value"]["registry_password"] == "[redacted]"


async def test_unknown_entry_is_404(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _admin(db_session)
    await db_session.commit()
    r = await client.get(f"/api/v1/audit/{uuid.uuid4()}", headers=h)
    assert r.status_code == 404


# ── Validation pass: the shapes the writers really store ────────────────

_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDSECRETBODY\n"
    "-----END PRIVATE KEY-----\n"
)
_FERNET = "gAAAAABlAbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcdefghijkl=="


def test_set_flags_survive_redaction() -> None:
    """Writers record a credential as ``<field>_set: true`` (audit-forward
    targets, DHCP servers, LG peers, ACME EAB). That flag is the detail an
    operator opens the entry for; turning it into ``[redacted]`` hid whether
    the secret was set at all."""
    from app.services.audit_redact import redact_audit_value

    out = redact_audit_value(
        {
            "smtp_password_set": True,
            "auth_header_set": False,
            "url_set": True,
            "eab_hmac_set": True,
            "md5_password_set": True,
            "snmp_community_set": True,
            "windows_credentials_set": True,
            "token_count": 3,
            "eab_kid": "kid-1",
        }
    )
    assert out == {
        "smtp_password_set": True,
        "auth_header_set": False,
        "url_set": True,
        "eab_hmac_set": True,
        "md5_password_set": True,
        "snmp_community_set": True,
        "windows_credentials_set": True,
        "token_count": 3,
        "eab_kid": "kid-1",
    }


def test_credential_names_the_support_bundle_regex_misses() -> None:
    from app.services.audit_redact import REDACTED, redact_audit_value

    out = redact_audit_value(
        {
            "community": "public-rw",  # SNMP v2c on a network device
            "snmp_community": "s3cret-comm",
            "snmp_v3_users": [
                {"username": "ops", "auth_pass": "authpw123", "priv_pass": "privpw123"}
            ],
            "client_key_pem": "abc",
            "account_key_pem": "abc",
            "headers": {"X-Custom": "opaque-credential"},
            "creds": {"user": "a", "pw": "b"},
            # Must stay readable.
            "communities": ["65000:100"],
            "header_names": ["X-Custom"],
            "private_ip": "10.0.0.1",
            "tsig_key_name": None,
        }
    )
    for k in ("community", "snmp_community", "client_key_pem", "account_key_pem"):
        assert out[k] == REDACTED, k
    assert out["snmp_v3_users"][0] == {
        "username": "ops",
        "auth_pass": REDACTED,
        "priv_pass": REDACTED,
    }
    assert out["headers"] == REDACTED and out["creds"] == REDACTED
    assert out["communities"] == ["65000:100"]
    assert out["header_names"] == ["X-Custom"]
    assert out["private_ip"] == "10.0.0.1"
    assert out["tsig_key_name"] is None


def test_value_shapes_under_innocent_keys() -> None:
    from app.services.audit_redact import REDACTED, redact_audit_value

    out = redact_audit_value(
        {
            "note": _PEM,
            "blob": _FERNET,
            "target": "postgresql://svc:hunter2@db/x",
            "hook": "https://hooks.slack.com/services/T000/B000/XXXXXXXX",
        }
    )
    # The shared PEM pattern matches the BEGIN line only; the body must not
    # survive it.
    assert out["note"] == REDACTED
    assert "SECRETBODY" not in str(out)
    assert _FERNET not in str(out)
    assert "hunter2" not in out["target"] and out["target"].endswith("@db/x")
    assert "XXXXXXXX" not in out["hook"]


async def test_odd_payload_shape_does_not_break_the_list(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The columns are typed dict but JSONB accepts anything; one bare-list
    payload must not 500 the whole audit page."""
    h = await _admin(db_session)
    row = AuditLog(
        action="update",
        resource_type="thing",
        resource_id="x",
        resource_display="x",
        user_display_name="alice",
        auth_source="local",
        result="success",
        new_value=["a", "b"],  # type: ignore[arg-type]
        changed_fields=["a"],
    )
    db_session.add(row)
    await db_session.commit()
    assert (await client.get("/api/v1/audit", headers=h)).status_code == 200
    r = await client.get("/api/v1/audit?include_details=true", headers=h)
    assert r.status_code == 200, r.text
    one = await client.get(f"/api/v1/audit/{row.id}", headers=h)
    assert one.status_code == 200, one.text
    assert one.json()["new_value"] == {"value": ["a", "b"]}


async def test_details_need_read_audit_log(client: AsyncClient, db_session: AsyncSession) -> None:
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Nobody",
        hashed_password=hash_password("x"),
        is_superadmin=False,
    )
    db_session.add(u)
    await db_session.flush()
    row = await _entry(db_session)
    h = {"Authorization": f"Bearer {create_access_token(str(u.id))}"}
    assert (await client.get(f"/api/v1/audit/{row.id}", headers=h)).status_code == 403
    r = await client.get("/api/v1/audit?include_details=true", headers=h)
    assert r.status_code == 403


async def test_mcp_tool_omits_details_unless_asked(db_session: AsyncSession) -> None:
    """The copilot's provider can be off-premises, so before/after values
    leave the box only on request, like the list endpoint's include_details."""
    from app.services.ai.tools.network import GetAuditHistoryArgs, get_audit_history

    row = await _entry(db_session)
    out = await get_audit_history(
        db_session, None, GetAuditHistoryArgs(resource_id=row.resource_id)  # type: ignore[arg-type]
    )
    assert len(out) == 1
    assert "old_value" not in out[0] and "new_value" not in out[0]
    assert out[0]["changed_fields"] == row.changed_fields


async def test_mcp_tool_redacts_the_same_way(db_session: AsyncSession) -> None:
    from app.services.ai.tools.network import GetAuditHistoryArgs, get_audit_history

    row = await _entry(db_session)
    out = await get_audit_history(
        db_session,
        None,  # type: ignore[arg-type]
        GetAuditHistoryArgs(resource_id=row.resource_id, include_details=True),
    )
    assert len(out) == 1
    assert out[0]["new_value"]["direction"] == "backward"
    assert out[0]["new_value"]["registry_password"] == "[redacted]"
    assert out[0]["old_value"]["api_key"] == "[redacted]"
    assert "s3cret" not in str(out) and _JWT not in str(out)


def test_backup_target_rows_written_by_older_builds_read_redacted() -> None:
    """Older builds recorded a backup target's edited ``config`` and a failed
    https_put run's full receiver URL as-is. Those rows stay stored as they
    were (the chain hashes them), so the read path must cover their shapes:
    storage connection strings, presigned S3 / GCS query strings, and the
    URL embedded in a run's error text."""
    from app.services.audit_redact import REDACTED, redact_audit_value

    stored_patch = {
        "config": {
            "connection_string": (
                "DefaultEndpointsProtocol=https;AccountName=acct;"
                "AccountKey=QUNDT1VOVEtFWUJBU0U2NA==;EndpointSuffix=core.windows.net"
            ),
            "url": (
                "https://bucket.s3.amazonaws.com/b.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256"
                "&X-Amz-Credential=AKIAEXAMPLE%2F20260101%2Fus-east-1%2Fs3%2Faws4_request"
                "&X-Amz-Expires=3600&X-Amz-Signature=deadbeefcafef00d0123456789abcdef"
            ),
            "secret_access_key": "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
            "bucket": "bucket",
        },
        "name": "offsite",
    }
    out = redact_audit_value(stored_patch)
    cfg = out["config"]
    assert cfg["connection_string"] == REDACTED
    assert "deadbeefcafef00d" not in cfg["url"]
    assert "AKIAEXAMPLE" not in cfg["url"]
    # Host, path and non-credential parameters stay readable.
    assert cfg["url"].startswith("https://bucket.s3.amazonaws.com/b.zip?")
    assert "X-Amz-Expires=3600" in cfg["url"]
    assert cfg["secret_access_key"] == REDACTED
    assert cfg["bucket"] == "bucket" and out["name"] == "offsite"

    error_detail = (
        "PUT to https://storage.googleapis.com/b/a.zip?X-Goog-Algorithm=GOOG4-RSA-SHA256"
        "&X-Goog-Credential=svc%40proj.iam.gserviceaccount.com%2F20260101"
        "&X-Goog-Signature=0a1b2c3d4e5f60718293a4b5c6d7e8f9 returned 403: denied"
    )
    redacted = redact_audit_value(error_detail)
    assert "0a1b2c3d4e5f6071" not in redacted
    assert "gserviceaccount" not in redacted
    assert redacted.endswith("returned 403: denied")
    # Idempotent: redacting the redacted text changes nothing.
    assert redact_audit_value(redacted) == redacted

    # A bare connection string under an innocent key is caught by value.
    assert (
        "QUNDT1VOVEtFWUJBU0U2NA"
        not in redact_audit_value({"note": stored_patch["config"]["connection_string"]})["note"]
    )


def test_openapi_include_details_names_error_detail_3043() -> None:
    from app.main import app

    params = app.openapi()["paths"]["/api/v1/audit"]["get"]["parameters"]
    desc = next(p for p in params if p["name"] == "include_details")["description"]
    for field in ("old_value", "new_value", "changed_fields", "error_detail"):
        assert field in desc


def test_openapi_integrity_description_matches_nightly_verify_3044() -> None:
    from app.main import app

    desc = app.openapi()["paths"]["/api/v1/audit/integrity"]["get"]["description"]
    flat = " ".join(desc.split())
    assert "pre-computes the same answer" not in flat
    assert "since its last clean run" in flat
    # The full pass starts only once the last one is MORE than 7 days old,
    # measured from when it finished, so a nightly task re-walks on the
    # eighth night; "at least every 7 days" would be a promise it breaks.
    assert "at least" not in flat
    assert "more than 7 days old" in flat


def test_full_pass_waits_until_the_last_one_is_over_7_days_old_3044() -> None:
    # The integrity route and the Audit Log badge describe the nightly
    # verify's full pass as starting once the last one is MORE than 7 days
    # old. Pin that rule, so the wording cannot drift from the code: a pass
    # that finished 7 days ago less a minute does not trigger one, which is
    # why a 02:00 nightly task re-walks on the eighth night, not the seventh.
    from datetime import UTC, datetime, timedelta

    from app.services.audit_chain import FULL_PASS_INTERVAL
    from app.tasks.audit_chain_verify import _full_pass_reason

    now = datetime.now(UTC)
    assert FULL_PASS_INTERVAL == timedelta(days=7)
    assert _full_pass_reason(now - timedelta(days=7) + timedelta(minutes=1), now) is None
    assert _full_pass_reason(now - timedelta(days=7, minutes=1), now) == "stale"
