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
