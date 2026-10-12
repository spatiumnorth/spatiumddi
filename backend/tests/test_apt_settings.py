"""Appliance APT host-config (issue #155) — renderer + bundle + API.

Covers the pure renderers (sources.list / proxy / auth), the
``apt_bundle`` shape + hash, the validate endpoint's structural checks,
and the PUT → GET round-trip with secret redaction (armoured key text +
auth passwords fold into ``*_set`` booleans, never returned plaintext).
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.settings import DEFAULT_APT_SOURCES, PlatformSettings
from app.services.appliance.apt import (
    apt_bundle,
    render_auth_conf,
    render_proxy_conf,
    render_sources_list,
    unattended_block,
)

pytestmark = pytest.mark.asyncio


async def _superadmin(db: AsyncSession) -> tuple[User, str]:
    u = User(
        username=f"admin-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:6]}@x.com",
        display_name="Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return u, create_access_token(str(u.id))


def _hdr(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _shim(**kw) -> PlatformSettings:
    s = PlatformSettings(id=0)
    s.apt_managed = kw.get("managed", True)
    s.apt_sources = kw.get("sources", [dict(x) for x in DEFAULT_APT_SOURCES])
    s.apt_gpg_keys = kw.get("gpg_keys", [])
    s.apt_proxy_http = kw.get("proxy_http", "")
    s.apt_proxy_https = kw.get("proxy_https", "")
    s.apt_proxy_no_proxy = kw.get("no_proxy", "")
    s.apt_auth = kw.get("auth", [])
    s.apt_unattended_upgrades_enabled = kw.get("unattended", True)
    # Issue #164 — unattended-upgrades policy (defaults mirror the model's
    # server_defaults so a shim behaves like a fresh row).
    s.apt_unattended_origins = kw.get(
        "unattended_origins", ["${distro_id}:${distro_codename}-security"]
    )
    s.apt_unattended_blocklist = kw.get("unattended_blocklist", [])
    s.apt_unattended_automatic_reboot = kw.get("unattended_automatic_reboot", False)
    s.apt_unattended_reboot_time = kw.get("unattended_reboot_time", "02:00")
    return s


# ── (a) pure renderers ──────────────────────────────────────────────


def test_render_sources_list_emits_enabled_only_with_signed_by() -> None:
    s = _shim(
        sources=[
            {
                "name": "Internal",
                "uri": "https://mirror.lan/debian",
                "suites": "trixie",
                "components": "main",
                "signed_by_key_id": "lan-key",
                "enabled": True,
            },
            {
                "name": "Disabled",
                "uri": "https://nope.lan/debian",
                "suites": "trixie",
                "components": "main",
                "signed_by_key_id": "",
                "enabled": False,
            },
        ]
    )
    out = render_sources_list(s)
    assert "https://mirror.lan/debian trixie main" in out
    assert "[signed-by=/etc/apt/keyrings/spatiumddi-lan-key.asc]" in out
    # The disabled source is omitted.
    assert "nope.lan" not in out


def test_render_proxy_conf_includes_no_proxy_direct() -> None:
    s = _shim(proxy_http="http://proxy.lan:3128/", no_proxy="localhost, mirror.lan")
    out = render_proxy_conf(s)
    assert 'Acquire::http::Proxy "http://proxy.lan:3128/";' in out
    assert 'Acquire::http::Proxy::localhost "DIRECT";' in out
    assert 'Acquire::http::Proxy::mirror.lan "DIRECT";' in out
    # No proxy configured → empty string (runner removes the file).
    assert render_proxy_conf(_shim()) == ""


def test_apt_bundle_disabled_when_unmanaged() -> None:
    b = apt_bundle(_shim(managed=False))
    assert b["enabled"] is False
    # #164 — the sources-disabled bundle still carries the unattended policy,
    # so its hash is non-empty (a policy change re-fires even with apt_managed
    # off). It is deterministic for a fixed policy.
    assert len(b["config_hash"]) == 64
    assert "unattended" in b
    assert apt_bundle(_shim(managed=False))["config_hash"] == b["config_hash"]
    # Managed flips sources on with its own stable non-empty hash.
    b2 = apt_bundle(_shim(managed=True))
    assert b2["enabled"] is True
    assert len(b2["config_hash"]) == 64
    # Deterministic — same settings → same hash.
    assert apt_bundle(_shim(managed=True))["config_hash"] == b2["config_hash"]


# ── (a2) unattended-upgrades policy (#164) ──────────────────────────


def test_unattended_block_shape_and_normalisation() -> None:
    u = unattended_block(
        _shim(
            unattended=True,
            unattended_origins=["  origin=Debian  ", "", "o=x"],
            unattended_blocklist=["linux-image-*", "  "],
            unattended_automatic_reboot=True,
            unattended_reboot_time="03:15",
        )
    )
    assert u["enabled"] is True
    # Blank entries dropped, surrounding whitespace stripped.
    assert u["origins"] == ["origin=Debian", "o=x"]
    assert u["blocklist"] == ["linux-image-*"]
    assert u["automatic_reboot"] is True
    assert u["reboot_time"] == "03:15"


def test_apt_bundle_hash_tracks_unattended_policy_when_unmanaged() -> None:
    # apt_managed off both times — only the unattended policy differs, and the
    # config_hash must still shift so the supervisor re-fires the host trigger.
    a = apt_bundle(_shim(managed=False, unattended_reboot_time="02:00"))["config_hash"]
    b = apt_bundle(_shim(managed=False, unattended_reboot_time="04:30"))["config_hash"]
    assert a != b
    # And the managed-shape hash also folds the policy in.
    c = apt_bundle(_shim(managed=True, unattended_automatic_reboot=False))["config_hash"]
    d = apt_bundle(_shim(managed=True, unattended_automatic_reboot=True))["config_hash"]
    assert c != d


async def test_put_get_unattended_policy_roundtrip(client: AsyncClient, db_session):
    _, token = await _superadmin(db_session)
    h = _hdr(token)
    r = await client.put(
        "/api/v1/settings",
        headers=h,
        json={
            "apt_unattended_upgrades_enabled": True,
            "apt_unattended_origins": ["${distro_id}:${distro_codename}-security", "o=Debian"],
            "apt_unattended_blocklist": ["linux-image-*"],
            "apt_unattended_automatic_reboot": True,
            "apt_unattended_reboot_time": "03:30",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["apt_unattended_origins"] == [
        "${distro_id}:${distro_codename}-security",
        "o=Debian",
    ]
    assert body["apt_unattended_blocklist"] == ["linux-image-*"]
    assert body["apt_unattended_automatic_reboot"] is True
    assert body["apt_unattended_reboot_time"] == "03:30"
    # The bundle carries the policy through to the host trigger.
    settings = await db_session.get(PlatformSettings, 1)
    assert settings is not None
    u = apt_bundle(settings)["unattended"]
    assert u["automatic_reboot"] is True
    assert u["reboot_time"] == "03:30"
    assert "o=Debian" in u["origins"]


async def test_put_rejects_bad_reboot_time(client: AsyncClient, db_session):
    _, token = await _superadmin(db_session)
    r = await client.put(
        "/api/v1/settings",
        headers=_hdr(token),
        json={"apt_unattended_reboot_time": "25:99"},
    )
    assert r.status_code == 422


async def test_put_rejects_control_char_in_origin(client: AsyncClient, db_session):
    _, token = await _superadmin(db_session)
    r = await client.put(
        "/api/v1/settings",
        headers=_hdr(token),
        json={"apt_unattended_origins": ['o=Debian\nUnattended-Upgrade::Foo "1"']},
    )
    assert r.status_code == 422
    # ASCII DEL (0x7f) is a control char too and must be rejected (Copilot review).
    r2 = await client.put(
        "/api/v1/settings",
        headers=_hdr(token),
        json={"apt_unattended_blocklist": ["nvidia-\x7f"]},
    )
    assert r2.status_code == 422


def test_render_auth_conf_skips_entries_without_password() -> None:
    # password_enc None → entry skipped (can't render a netrc line).
    s = _shim(auth=[{"machine": "mirror.lan", "login": "bob", "password_enc": None}])
    assert render_auth_conf(s) == ""


# ── (b) validate endpoint ───────────────────────────────────────────


async def test_validate_flags_no_enabled_sources(client: AsyncClient, db_session):
    _, token = await _superadmin(db_session)
    r = await client.post(
        "/api/v1/settings/apt/validate",
        headers=_hdr(token),
        json={"apt_sources": []},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["valid"] is False
    assert any("no enabled sources" in e.lower() for e in body["errors"])


async def test_validate_warns_on_missing_signing_key(client: AsyncClient, db_session):
    _, token = await _superadmin(db_session)
    r = await client.post(
        "/api/v1/settings/apt/validate",
        headers=_hdr(token),
        json={
            "apt_sources": [
                {
                    "name": "Internal",
                    "uri": "https://mirror.lan/debian",
                    "suites": "trixie",
                    "components": "main",
                    "signed_by_key_id": "ghost-key",
                    "enabled": True,
                }
            ],
            "apt_gpg_key_ids": [],
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["valid"] is True  # structurally valid; missing key is a warning
    assert any("NO_PUBKEY" in w for w in body["warnings"])
    assert "mirror.lan/debian" in body["sources_list_preview"]


async def test_validate_rejects_bad_uri_scheme(client: AsyncClient, db_session):
    _, token = await _superadmin(db_session)
    r = await client.post(
        "/api/v1/settings/apt/validate",
        headers=_hdr(token),
        json={"apt_sources": [{"uri": "ftp-bad://x", "suites": "trixie", "enabled": True}]},
    )
    # The AptSourceUpdate validator rejects the scheme → 422 at the schema.
    assert r.status_code == 422


async def test_put_rejects_path_injection_in_signed_by(client: AsyncClient, db_session):
    """signed_by_key_id flows into the keyring path — a separator/escape
    must be rejected at the schema (not sanitised silently)."""
    _, token = await _superadmin(db_session)
    r = await client.put(
        "/api/v1/settings",
        headers=_hdr(token),
        json={
            "apt_managed": True,
            "apt_sources": [
                {
                    "uri": "https://mirror.lan/debian",
                    "suites": "trixie",
                    "signed_by_key_id": "../../etc/evil",
                    "enabled": True,
                }
            ],
        },
    )
    assert r.status_code == 422


async def test_put_rejects_proxy_with_quote(client: AsyncClient, db_session):
    _, token = await _superadmin(db_session)
    r = await client.put(
        "/api/v1/settings",
        headers=_hdr(token),
        json={"apt_proxy_http": 'http://h" ;}'},
    )
    assert r.status_code == 422


# ── (c) PUT → GET redaction round-trip ──────────────────────────────


async def test_put_then_get_redacts_secrets(client: AsyncClient, db_session):
    _, token = await _superadmin(db_session)
    h = _hdr(token)

    r = await client.put(
        "/api/v1/settings",
        headers=h,
        json={
            "apt_managed": True,
            "apt_sources": [
                {
                    "name": "Internal",
                    "uri": "https://mirror.lan/debian",
                    "suites": "trixie",
                    "components": "main",
                    "signed_by_key_id": "lan-key",
                    "enabled": True,
                }
            ],
            "apt_gpg_keys": [
                {
                    "key_id": "lan-key",
                    "comment": "LAN mirror",
                    "armoured_text": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END PGP PUBLIC KEY BLOCK-----",
                }
            ],
            "apt_auth": [{"machine": "mirror.lan", "login": "bob", "password": "s3cret"}],
            "apt_proxy_http": "http://proxy.lan:3128/",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["apt_managed"] is True
    # Secrets folded to booleans — never the armoured text / password.
    assert body["apt_gpg_keys"][0]["armoured_text_set"] is True
    assert "armoured_text" not in body["apt_gpg_keys"][0]
    assert body["apt_auth"][0]["password_set"] is True
    assert "password" not in body["apt_auth"][0]

    # The rendered bundle reflects the stored (decrypted) config.
    settings = await db_session.get(PlatformSettings, 1)
    assert settings is not None
    bundle = apt_bundle(settings)
    assert bundle["enabled"] is True
    assert "lan-key" in bundle["keyrings"]
    assert "BEGIN PGP PUBLIC KEY BLOCK" in bundle["keyrings"]["lan-key"]
    assert "machine mirror.lan login bob password s3cret" in bundle["auth_conf"]

    # NN #4 — the APT change wrote a dedicated audit row, and it never
    # records the armoured key text or the password.
    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.resource_type == "platform_settings",
                    AuditLog.resource_id == "apt",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    nv = rows[0].new_value or {}
    assert nv.get("managed") is True
    assert nv.get("gpg_key_count") == 1
    blob = repr(nv)
    assert "s3cret" not in blob and "PGP PUBLIC KEY" not in blob


async def test_put_preserves_secret_on_omit(client: AsyncClient, db_session):
    """Editing a GPG key's comment without re-pasting the armoured text
    preserves the stored ciphertext (merge-by-key_id)."""
    _, token = await _superadmin(db_session)
    h = _hdr(token)
    await client.put(
        "/api/v1/settings",
        headers=h,
        json={
            "apt_managed": True,
            "apt_gpg_keys": [{"key_id": "k1", "comment": "first", "armoured_text": "KEYBODY"}],
        },
    )
    # Re-PUT with no armoured_text → preserve.
    await client.put(
        "/api/v1/settings",
        headers=h,
        json={"apt_gpg_keys": [{"key_id": "k1", "comment": "renamed"}]},
    )
    settings = await db_session.get(PlatformSettings, 1)
    assert settings is not None
    bundle = apt_bundle(settings)
    assert bundle["keyrings"].get("k1") == "KEYBODY"


async def test_put_rejects_a_blocklist_entry_that_is_not_a_regex(client: AsyncClient, db_session):
    """#1384: unattended-upgrades reads each entry as a regex. ``*`` (a glob,
    which the form used to ask for) does not compile, and would break the
    daily run on the host if it got there."""
    _, token = await _superadmin(db_session)
    r = await client.put(
        "/api/v1/settings",
        headers=_hdr(token),
        json={"apt_unattended_blocklist": ["*"]},
    )
    assert r.status_code == 422
    assert "regular expression" in r.text
    ok = await client.put(
        "/api/v1/settings",
        headers=_hdr(token),
        json={"apt_unattended_blocklist": ["linux-image-", "^openssl$"]},
    )
    assert ok.status_code == 200, ok.text


async def test_put_rejects_a_double_quote_in_unattended_entries(client: AsyncClient, db_session):
    """#1384: apt.conf has no escape for a double quote inside a quoted string,
    so an entry carrying one would make apt-config reject the whole policy
    file on the host. Refused at save instead, for both lists."""
    _, token = await _superadmin(db_session)
    for field in ("apt_unattended_blocklist", "apt_unattended_origins"):
        r = await client.put(
            "/api/v1/settings",
            headers=_hdr(token),
            json={field: ['foo"bar']},
        )
        assert r.status_code == 422, (field, r.text)
        assert "double quote" in r.text
    # A backslash is legal: it is written to apt.conf verbatim, which is
    # exactly what unattended-upgrades then compiles.
    ok = await client.put(
        "/api/v1/settings",
        headers=_hdr(token),
        json={"apt_unattended_blocklist": [r"linux-image-\d"]},
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["apt_unattended_blocklist"] == [r"linux-image-\d"]


# ── GHSA-j77h-pqg7-h2g4 — proxy URL credentials never leave the server ──

_PROXY_WITH_CREDS = "http://bob:hunter2@proxy.lan:3128/"


async def _viewer(db: AsyncSession) -> str:
    u = User(
        username=f"viewer-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:6]}@x.com",
        display_name="Viewer",
        hashed_password=hash_password("x"),
        is_superadmin=False,
    )
    db.add(u)
    await db.flush()
    return create_access_token(str(u.id))


async def _store_proxy(db: AsyncSession, http: str, https: str = "") -> PlatformSettings:
    settings = await db.get(PlatformSettings, 1)
    if settings is None:
        settings = PlatformSettings(id=1)
        db.add(settings)
    settings.apt_proxy_http = http
    settings.apt_proxy_https = https
    await db.flush()
    return settings


async def test_get_settings_masks_proxy_credentials(client: AsyncClient, db_session):
    await _store_proxy(db_session, _PROXY_WITH_CREDS, "https://tok3n@proxy.lan:3129")
    r = await client.get("/api/v1/settings", headers=_hdr(await _viewer(db_session)))
    assert r.status_code == 200, r.text
    assert "hunter2" not in r.text and "bob" not in r.text and "tok3n" not in r.text
    body = r.json()
    # The host stays visible: "which proxy?" is a real question, the
    # credential is not part of the answer.
    assert body["apt_proxy_http"] == "http://***@proxy.lan:3128/"
    assert body["apt_proxy_https"] == "https://***@proxy.lan:3129"


async def test_get_settings_leaves_a_credential_free_proxy_alone(client: AsyncClient, db_session):
    await _store_proxy(db_session, "http://proxy.lan:3128/")
    _, token = await _superadmin(db_session)
    body = (await client.get("/api/v1/settings", headers=_hdr(token))).json()
    assert body["apt_proxy_http"] == "http://proxy.lan:3128/"


async def test_put_of_the_masked_value_keeps_the_stored_credential(client: AsyncClient, db_session):
    await _store_proxy(db_session, _PROXY_WITH_CREDS)
    _, token = await _superadmin(db_session)
    h = _hdr(token)
    masked = (await client.get("/api/v1/settings", headers=h)).json()["apt_proxy_http"]

    # The form re-sends what it was shown.
    r = await client.put("/api/v1/settings", headers=h, json={"apt_proxy_http": masked})
    assert r.status_code == 200, r.text
    assert "hunter2" not in r.text
    settings = await db_session.get(PlatformSettings, 1)
    await db_session.refresh(settings)
    assert settings.apt_proxy_http == _PROXY_WITH_CREDS

    # Editing the host / port while leaving the mask keeps the credential.
    r = await client.put(
        "/api/v1/settings", headers=h, json={"apt_proxy_http": "http://***@proxy2.lan:8080/"}
    )
    assert r.status_code == 200, r.text
    await db_session.refresh(settings)
    assert settings.apt_proxy_http == "http://bob:hunter2@proxy2.lan:8080/"

    # A real new credential replaces it; clearing still clears.
    r = await client.put(
        "/api/v1/settings", headers=h, json={"apt_proxy_http": "http://amy:pw2@proxy2.lan:8080/"}
    )
    assert r.status_code == 200, r.text
    await db_session.refresh(settings)
    assert settings.apt_proxy_http == "http://amy:pw2@proxy2.lan:8080/"
    r = await client.put("/api/v1/settings", headers=h, json={"apt_proxy_http": ""})
    assert r.status_code == 200, r.text
    await db_session.refresh(settings)
    assert settings.apt_proxy_http == ""


async def test_put_of_a_mask_with_no_stored_credential_is_refused(client: AsyncClient, db_session):
    await _store_proxy(db_session, "http://proxy.lan:3128/")
    _, token = await _superadmin(db_session)
    r = await client.put(
        "/api/v1/settings",
        headers=_hdr(token),
        json={"apt_proxy_http": "http://***@proxy.lan:3128/"},
    )
    assert r.status_code == 422, r.text


async def test_find_apt_settings_masks_proxy_credentials(db_session):
    from app.services.ai.tools.apt import FindAptSettingsArgs, find_apt_settings

    await _store_proxy(db_session, _PROXY_WITH_CREDS, "https://tok3n@proxy.lan:3129")
    user, _ = await _superadmin(db_session)
    out = await find_apt_settings(db_session, user, FindAptSettingsArgs())
    assert out["proxy_http"] == "http://***@proxy.lan:3128/"
    assert out["proxy_https"] == "https://***@proxy.lan:3129"
    assert "hunter2" not in repr(out) and "tok3n" not in repr(out)


async def test_support_bundle_settings_drop_proxy_credentials(db_session):
    from app.services.support_bundle.collect import collect_platform_settings
    from app.services.support_bundle.scrub import Scrubber

    # A token-only userinfo has no ``user:pass`` shape for the bundle's
    # text rule to catch, and the unscrubbed mode keeps hostnames.
    await _store_proxy(db_session, "http://tok3n@proxy.lan:3128/", _PROXY_WITH_CREDS)
    out = await collect_platform_settings(db_session, Scrubber(enabled=False))
    assert "tok3n" not in out and "hunter2" not in out
