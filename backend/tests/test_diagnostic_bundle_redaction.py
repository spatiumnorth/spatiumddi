"""What the appliance diagnostic bundle and the support bundle let out.

Both archives are handed to someone outside the install, so the
assertions are on the archive contents: feed known credentials in
through the environment, the host ``.env`` file and the logs, and assert
they are absent from every file that comes out.
"""

from __future__ import annotations

import zipfile
from datetime import UTC, datetime
from io import BytesIO
from types import SimpleNamespace

import pytest

from app.services.appliance import diagnostics
from app.services.support_bundle import collect
from app.services.support_bundle.scrub import Scrubber, redact_secrets

LG_PSK = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718"
DNS_PSK = "f00dfeedf00dfeedf00dfeedf00dfeedf00dfeed"
DB_PASSWORD = "pgPassw0rdValue"
REDIS_PASSWORD = "redisPassw0rdValue"
VENDOR_CREDENTIAL = "vendorCredentialValue"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27u"
FERNET = "gAAAAABm1234567890abcdefghijklmnopqrstuv"

SECRETS = (LG_PSK, DNS_PSK, DB_PASSWORD, REDIS_PASSWORD, VENDOR_CREDENTIAL, JWT, FERNET)


def _secret_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LG_AGENT_KEY", LG_PSK)
    monkeypatch.setenv("DNS_AGENT_KEY", DNS_PSK)
    monkeypatch.setenv(
        "DATABASE_URL", f"postgresql+asyncpg://spatiumddi:{DB_PASSWORD}@postgres:5432/db"
    )
    monkeypatch.setenv("REDIS_URL", f"redis://:{REDIS_PASSWORD}@redis:6379/0")
    monkeypatch.setenv("CELERY_BROKER_URL", f"sentinel://:{REDIS_PASSWORD}@r0:26379,r1:26379/1")
    # A name no denylist anticipates.
    monkeypatch.setenv("ACME_VENDOR_AUTH", VENDOR_CREDENTIAL)
    monkeypatch.setenv("LOG_LEVEL", "INFO")
    monkeypatch.setenv("SPATIUMDDI_API_SERVICE_HOST", "10.43.0.10")


def _bundle(monkeypatch: pytest.MonkeyPatch, tmp_path, pod_log: str, env_file: str | None):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "firstboot.log").write_text(pod_log)
    monkeypatch.setattr(diagnostics, "_log_dir", lambda: log_dir)

    host_env = tmp_path / ".env"
    if env_file is not None:
        host_env.write_text(env_file)
    monkeypatch.setattr(diagnostics, "_HOST_ENV_FILE", host_env)

    monkeypatch.setattr(
        diagnostics,
        "list_containers",
        lambda: [SimpleNamespace(name="spatium-api-0", is_spatium=True)],
    )
    monkeypatch.setattr(diagnostics, "get_container_logs", lambda name, tail=500: pod_log)
    monkeypatch.setattr(
        diagnostics,
        "run_self_test",
        lambda: diagnostics.SelfTestReport(run_at=datetime.now(tz=UTC), overall_ok=True, checks=[]),
    )
    blob = diagnostics.generate_diagnostic_bundle()
    with zipfile.ZipFile(BytesIO(blob)) as zf:
        return {n: zf.read(n).decode() for n in zf.namelist()}


def _assert_no_secret(members: dict[str, str]) -> None:
    for name, body in members.items():
        for secret in SECRETS:
            assert secret not in body, f"{secret[:6]}… leaked in {name}"


def test_appliance_bundle_env_dump_carries_no_secret_value(monkeypatch, tmp_path):
    _secret_env(monkeypatch)
    members = _bundle(monkeypatch, tmp_path, pod_log="ok\n", env_file=None)

    _assert_no_secret(members)
    env = members["system/env.redacted"].splitlines()
    # Keys stay visible so support can see what is set.
    assert "LG_AGENT_KEY=[REDACTED]" in env
    assert "REDIS_URL=[REDACTED]" in env
    assert "ACME_VENDOR_AUTH=[REDACTED]" in env
    # Known non-secret settings keep their values.
    assert "LOG_LEVEL=INFO" in env
    assert "SPATIUMDDI_API_SERVICE_HOST=10.43.0.10" in env


def test_appliance_bundle_logs_are_swept_for_credentials(monkeypatch, tmp_path):
    log = (
        "worker started\n"
        f"connect postgresql://spatiumddi:{DB_PASSWORD}@postgres/db failed\n"
        f"broker redis://:{REDIS_PASSWORD}@redis:6379/0 unreachable\n"
        f"Authorization: Bearer {JWT}\n"
        f"stored {FERNET}\n"
    )
    members = _bundle(monkeypatch, tmp_path, pod_log=log, env_file=None)

    _assert_no_secret(members)
    assert "worker started" in members["pods/spatium-api-0.log"]
    assert "worker started" in members["logs/firstboot.log"]
    assert "@redis:6379/0 unreachable" in members["pods/spatium-api-0.log"]


def test_appliance_bundle_host_env_file_is_redacted(monkeypatch, tmp_path):
    env_file = (
        f"LG_AGENT_KEY={LG_PSK}\n"
        f"export DNS_AGENT_KEY={DNS_PSK}\n"
        f"# ACME_VENDOR_AUTH={VENDOR_CREDENTIAL}\n"
        f'ACME_PEM="first line\n{FERNET}\nlast"\n'
        "LOG_LEVEL=DEBUG\n"
        "EMPTY_ONE=\n"
    )
    members = _bundle(monkeypatch, tmp_path, pod_log="ok\n", env_file=env_file)

    _assert_no_secret(members)
    redacted = members["config/env.redacted"].splitlines()
    assert "LG_AGENT_KEY=[REDACTED]" in redacted
    assert "export DNS_AGENT_KEY=[REDACTED]" in redacted
    assert "LOG_LEVEL=DEBUG" in redacted
    assert "EMPTY_ONE=" in redacted
    assert 'last"' not in members["config/env.redacted"]


def test_support_bundle_env_carries_no_secret_value(monkeypatch):
    _secret_env(monkeypatch)
    env = collect.collect_environment(Scrubber(seed="fixed"))

    for secret in SECRETS:
        assert secret not in env
    lines = env.splitlines()
    assert "ACME_VENDOR_AUTH=[REDACTED]" in lines
    assert "LOG_LEVEL=INFO" in lines


@pytest.mark.parametrize(
    "url",
    [
        f"redis://:{REDIS_PASSWORD}@redis:6379/0",
        f"sentinel://:{REDIS_PASSWORD}@r0:26379,r1:26379/1",
        f"postgresql://u:p@ss{REDIS_PASSWORD}@postgres:5432/db",
    ],
)
def test_url_passwords_are_removed_whatever_the_username(url):
    once, kinds = redact_secrets(f"url={url} next")
    assert REDIS_PASSWORD not in once
    assert "url-credentials" in kinds
    assert once.endswith(" next")
    # Running the sweep again over its own output finds nothing more.
    twice, again = redact_secrets(once)
    assert twice == once and again == []
