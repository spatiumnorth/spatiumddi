"""#1772: Technitium refusing the agent's admin credentials.

Re-provisioning logs in as ``admin`` with the stored bootstrap password.
When that no longer works (password changed, state volume lost, TOTP on),
the agent must say so specifically and STOP presenting the password —
Technitium blocks the loopback client after 5 failed logins.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from spatium_dns_agent.drivers import technitium
from spatium_dns_agent.drivers.technitium import (
    TechnitiumCredentialsError,
    TechnitiumDriver,
)


def _post_returning(body: dict[str, Any], seen: list[str]):
    def _post(url: str, **kw: Any) -> httpx.Response:
        seen.append(url)
        return httpx.Response(200, json=body, request=httpx.Request("POST", url))

    return _post


def test_bad_credentials_is_named_and_not_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = TechnitiumDriver(state_dir=tmp_path)
    seen: list[str] = []
    monkeypatch.setattr(
        technitium.httpx,
        "post",
        _post_returning(
            {"status": "error", "errorMessage": "Invalid username or password for user: admin"},
            seen,
        ),
    )
    with pytest.raises(TechnitiumCredentialsError) as ei:
        d._create_api_token()
    assert ei.value.reason == "bad-credentials"
    assert "bad-credentials" in str(ei.value)
    # Every further attempt inside the window is refused locally.
    for _ in range(10):
        with pytest.raises(TechnitiumCredentialsError):
            d._get_api_token()
    assert len(seen) == 1


def test_2fa_required_is_named(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    d = TechnitiumDriver(state_dir=tmp_path)
    monkeypatch.setattr(
        technitium.httpx,
        "post",
        _post_returning({"status": "2fa-required", "errorMessage": "TOTP is required"}, []),
    )
    with pytest.raises(TechnitiumCredentialsError) as ei:
        d._create_api_token()
    assert ei.value.reason == "2fa-required"
    assert "two-factor" in str(ei.value)


def test_retry_after_window_or_password_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = TechnitiumDriver(state_dir=tmp_path)
    seen: list[str] = []
    monkeypatch.setattr(
        technitium.httpx,
        "post",
        _post_returning({"status": "error", "errorMessage": "Invalid username or password"}, seen),
    )
    with pytest.raises(TechnitiumCredentialsError):
        d._create_api_token()
    # Operator restores a different password in the agent state: retry now.
    d._admin_password_path().write_text("new-password\n")
    with pytest.raises(TechnitiumCredentialsError):
        d._create_api_token()
    assert len(seen) == 2
    # Window elapsed: one more attempt is allowed.
    monkeypatch.setattr(technitium.time, "time", lambda: 10**10)
    with pytest.raises(TechnitiumCredentialsError):
        d._create_api_token()
    assert len(seen) == 3


def test_call_surfaces_the_specific_reason_not_token_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = TechnitiumDriver(state_dir=tmp_path)
    d._write_secret(d._api_token_path(), "stale")
    monkeypatch.setattr(
        d, "_request", lambda *a, **k: httpx.Response(200, json={"status": "invalid-token"})
    )
    monkeypatch.setattr(
        technitium.httpx,
        "post",
        _post_returning({"status": "error", "errorMessage": "Invalid username or password"}, []),
    )
    with pytest.raises(RuntimeError, match="bad-credentials"):
        d._call("stale", "POST", "zones/list", {})


def test_other_createtoken_errors_stay_transient(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    d = TechnitiumDriver(state_dir=tmp_path)
    seen: list[str] = []
    monkeypatch.setattr(
        technitium.httpx, "post", _post_returning({"status": "error", "errorMessage": "boom"}, seen)
    )
    assert d._create_api_token() is None
    assert d._create_api_token() is None
    assert len(seen) == 2


def test_a_blocked_address_is_named_locked_out_and_not_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``AuthManager.cs`` answers a blocked address before checking the
    password; without a verdict every record op re-asked."""
    d = TechnitiumDriver(state_dir=tmp_path)
    seen: list[str] = []
    monkeypatch.setattr(
        technitium.httpx,
        "post",
        _post_returning(
            {
                "status": "error",
                "errorMessage": "Max limit of 5 attempts exceeded. Access blocked for 300 seconds.",
            },
            seen,
        ),
    )
    with pytest.raises(TechnitiumCredentialsError) as ei:
        d._create_api_token()
    assert ei.value.reason == "locked-out"
    with pytest.raises(TechnitiumCredentialsError):
        d._get_api_token()
    assert len(seen) == 1


def test_suppressed_attempts_report_the_same_error_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The apply-status error must stay steady across retries, not lose
    Technitium's own wording after the first failure."""
    d = TechnitiumDriver(state_dir=tmp_path)
    msg = "Invalid username or password for user: admin"
    monkeypatch.setattr(
        technitium.httpx, "post", _post_returning({"status": "error", "errorMessage": msg}, [])
    )
    with pytest.raises(TechnitiumCredentialsError) as first:
        d._create_api_token()
    with pytest.raises(TechnitiumCredentialsError) as again:
        d._get_api_token()
    assert str(again.value) == str(first.value)
    assert msg in str(again.value)


def test_refused_credentials_report_reverted_not_revert_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Technitium's reload phase is API calls; a refused login means none went
    through. Re-applying the previous bundle would only repeat the refusal
    and report ``revert_failed`` ("running state unknown", critical) for a
    daemon that is still serving. It must read as one steady ``reverted``."""
    from spatium_dns_agent.cache import commit_config, ensure_layout, save_config
    from spatium_dns_agent.config_apply import STATUS_REVERTED, ApplyStatus
    from spatium_dns_agent.sync import SyncLoop

    class _Heartbeat:
        def __init__(self) -> None:
            self.daemon_status: dict[str, Any] = {}
            self.pending_acks: list[dict[str, Any]] = []
            self.failed_ops_count = 0
            self.config_apply = ApplyStatus()

    class _Cfg:
        state_dir = tmp_path
        control_plane_url = "http://cp.invalid"
        insecure_skip_tls_verify = False
        tls_ca_path = None

    ensure_layout(tmp_path)
    d = TechnitiumDriver(state_dir=tmp_path)
    reloads: list[int] = []

    def _swap() -> None:
        reloads.append(1)
        d._get_api_token()

    monkeypatch.setattr(d, "render", lambda bundle: None)
    monkeypatch.setattr(d, "validate", lambda: None)
    monkeypatch.setattr(d, "swap_and_reload", _swap)
    seen: list[str] = []
    monkeypatch.setattr(
        technitium.httpx,
        "post",
        _post_returning({"status": "error", "errorMessage": "Invalid username or password"}, seen),
    )
    # Built before any bundle is cached, so its cache bootstrap applies nothing.
    loop = SyncLoop(_Cfg(), ["tok"], d, _Heartbeat())  # type: ignore[arg-type]
    good = {"etag": "good", "structural_etag": "s-good", "zones": []}
    save_config(tmp_path, good, "good")
    commit_config(tmp_path, "good")

    bad = {"etag": "bad", "structural_etag": "s-bad", "zones": []}
    assert loop._apply_with_revert(bad, "bad") is False
    assert loop.apply_status.status == STATUS_REVERTED
    assert "bad-credentials" in (loop.apply_status.error or "")
    assert "revert also failed" not in (loop.apply_status.error or "")
    assert reloads == [1]  # no revert re-apply
    assert len(seen) == 1  # one login, not one per revert
