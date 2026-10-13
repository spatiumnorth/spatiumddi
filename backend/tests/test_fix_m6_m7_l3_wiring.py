"""Regression tests for #400 / GHSA-mj4g-hw3m-62rm — global-wiring
hardening cluster (M6 CORS, M7 demo-mode prod guard, L3 TrustedHost).

M6: a wildcard ``*`` mixed with explicit CORS origins must NOT enable
    credentials (the "reflect every Origin + send credentials" combo).
M7: ``DEMO_MODE=1`` must hard-fail if real configured deployment data
    (backup targets / integrations / auth providers) is present, so the
    unlocked admin/admin demo seed can't silently leak onto prod.
L3: TrustedHostMiddleware is wired from ``TRUSTED_HOSTS`` config and
    rejects forged Host headers when restricted, while the ``["*"]``
    default keeps existing deploys working.
"""

from __future__ import annotations

import pytest

from app.config import Settings, settings


# --------------------------------------------------------------------------
# M6 — CORS wildcard never co-exists with credentials
# --------------------------------------------------------------------------
def test_m6_plain_wildcard_collapses_and_disables_credentials() -> None:
    s = Settings(cors_origins="*")
    assert s.cors_origins_list == ["*"]
    # Middleware keys allow_credentials off (list == ["*"]) → disabled.
    assert (s.cors_origins_list != ["*"]) is False


def test_m6_explicit_origins_enable_credentials() -> None:
    s = Settings(cors_origins="https://a.example.com,https://b.example.com")
    assert s.cors_origins_list == [
        "https://a.example.com",
        "https://b.example.com",
    ]
    # No wildcard present → credentials may be enabled for the pinned origins.
    assert (s.cors_origins_list != ["*"]) is True


def test_m6_wildcard_mixed_with_explicit_collapses_to_wildcard() -> None:
    """The core M6 vuln: ``*`` mixed with an explicit origin previously
    produced ``["*", "https://app"]`` (!= ["*"]) which flipped credentials
    ON while ``*`` still reflected every Origin. Must collapse to ``["*"]``
    so credentials stay OFF."""
    for raw in (
        "*,https://app.example.com",
        "https://app.example.com,*",
        "https://a.example.com, * ,https://b.example.com",
    ):
        s = Settings(cors_origins=raw)
        assert s.cors_origins_list == ["*"], raw
        # Therefore the middleware computes allow_credentials=False.
        assert (s.cors_origins_list != ["*"]) is False, raw


# --------------------------------------------------------------------------
# L3 — TrustedHosts config + middleware wiring
# --------------------------------------------------------------------------
def test_l3_trusted_hosts_default_is_open() -> None:
    s = Settings()
    assert s.trusted_hosts_list == ["*"]


def test_l3_trusted_hosts_explicit_list() -> None:
    s = Settings(trusted_hosts="ddi.example.com, *.example.com")
    assert s.trusted_hosts_list == ["ddi.example.com", "*.example.com"]


def test_l3_trusted_hosts_wildcard_mixed_collapses() -> None:
    s = Settings(trusted_hosts="ddi.example.com,*")
    assert s.trusted_hosts_list == ["*"]


def test_l3_trustedhost_middleware_is_wired() -> None:
    """The middleware must actually be installed on the app stack."""
    from starlette.middleware.trustedhost import TrustedHostMiddleware

    from app.main import create_app

    app = create_app()
    classes = {m.cls for m in app.user_middleware}
    # Subclassed in #1868 so a refused Host is named in the log.
    assert any(issubclass(c, TrustedHostMiddleware) for c in classes)


async def test_l3_forged_host_rejected_when_restricted(monkeypatch) -> None:
    """With TRUSTED_HOSTS pinned, a request carrying a foreign Host header
    is 400'd by TrustedHostMiddleware; the allowed host still passes."""
    from httpx import ASGITransport, AsyncClient

    from app.main import create_app

    monkeypatch.setattr(settings, "trusted_hosts", "allowed.example.com")
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://allowed.example.com") as ac:
        ok = await ac.get("/health/live")
        assert ok.status_code == 200
        bad = await ac.get("/health/live", headers={"host": "evil.example.com"})
        assert bad.status_code == 400


# --------------------------------------------------------------------------
# M7 — DEMO_MODE may not boot on a real install
# --------------------------------------------------------------------------
async def test_m7_demo_guard_noop_when_demo_off(db_session, monkeypatch) -> None:
    """Guard is a no-op when DEMO_MODE is off, regardless of data."""
    from app.main import _assert_demo_mode_not_on_prod_data

    monkeypatch.setattr(settings, "demo_mode", False)
    # Must not raise even if prod-signal tables hold rows.
    await _assert_demo_mode_not_on_prod_data()


async def test_m7_demo_guard_passes_on_empty_demo_install(monkeypatch) -> None:
    """A genuine demo image has empty prod-signal tables — the guard must
    let it boot (legitimate demo flow preserved)."""
    from app.main import _assert_demo_mode_not_on_prod_data

    monkeypatch.setattr(settings, "demo_mode", True)
    await _assert_demo_mode_not_on_prod_data()


async def test_m7_demo_guard_fails_on_prod_backup_target(db_session, monkeypatch) -> None:
    """DEMO_MODE=1 with a configured backup target = a leaked demo flag on
    a real install. Must hard-fail boot."""
    from app.main import _assert_demo_mode_not_on_prod_data
    from app.models.backup import BackupTarget

    db_session.add(
        BackupTarget(
            name="prod-s3",
            kind="s3",
            config={"bucket": "prod"},
            passphrase_encrypted=b"x",
        )
    )
    await db_session.commit()

    monkeypatch.setattr(settings, "demo_mode", True)
    with pytest.raises(RuntimeError, match="DEMO_MODE=1"):
        await _assert_demo_mode_not_on_prod_data()
