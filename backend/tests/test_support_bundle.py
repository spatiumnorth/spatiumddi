"""Support bundle: scrubbing, collection, and the API gates (issue #875).

The failure mode this feature has is *leaking a credential onto a public
GitHub issue*, and that is not recoverable — the attachment URL follows
repo visibility and deleting the comment does not purge the file. So the
bulk of these tests are adversarial: feed known secrets and identifiers
through and assert their absence, rather than assert the happy path.
"""

from __future__ import annotations

import ipaddress
import json
import zipfile
from io import BytesIO

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.services.support_bundle import generate
from app.services.support_bundle.scrub import (
    Scrubber,
    ScrubReport,
    looks_secret_key,
    redact_secrets,
    safety_net,
)


async def _user(db: AsyncSession, username: str, *, superadmin: bool) -> tuple[User, str]:
    user = User(
        username=username,
        email=f"{username}@example.com",
        display_name=username,
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=superadmin,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return user, create_access_token(str(user.id))


# ── Hard-exclude tier ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("blob", "kind"),
    [
        ("gAAAAABm1234567890abcdefghijklmnop", "fernet"),
        ("$2b$12$" + "a" * 53, "password-hash"),
        ("$argon2id$v=19$m=65536,t=3,p=4$abcdefghijklmnop", "password-hash"),
        ("-----BEGIN RSA PRIVATE KEY-----", "pem"),
        ("-----BEGIN PRIVATE KEY-----", "pem"),
        ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27u", "jwt"),
        ("123456789:ABCdefGHIjklMNOpqrSTUvwxYZ0123456_-x", "telegram-bot-token"),
        (
            "https://api.telegram.org/bot123456789:ABCdefGHIjklMNOpqrSTUvwxYZ0123456_-x/sendMessage",
            "telegram-bot-token",
        ),
    ],
)
def test_secret_shapes_are_removed(blob: str, kind: str) -> None:
    cleaned, kinds = redact_secrets(f"prefix {blob} suffix")
    assert blob not in cleaned, f"{kind} survived redaction"
    assert kind in kinds
    # Surrounding text must survive — a redactor that eats the log line
    # around the secret destroys the diagnostic value of the file.
    assert "prefix" in cleaned and "suffix" in cleaned


def test_secrets_are_removed_even_when_scrubbing_is_off() -> None:
    """The unscrubbed bundle exists so an operator can read their own
    hostnames. There is no version of that which is improved by shipping
    the key that decrypts their database."""
    plain = Scrubber(enabled=False, seed="s")
    out = plain.text("token=gAAAAABm1234567890abcdefghij host=real.corp.example ip=10.1.2.3")
    assert "gAAAAABm1234567890abcdefghij" not in out
    # …while the identifiers it exists to preserve are untouched.
    assert "real.corp.example" in out
    assert "10.1.2.3" in out


@pytest.mark.parametrize(
    "name",
    [
        "password",
        "SECRET_KEY",
        "api_key",
        "apiKey",
        "credentials_encrypted",
        "dns_agent_psk",
        "tsig_secret",
        "ssh_authorized_keys",
        "apt_gpg_keys",
        "webhook_bearer",
        "session_id",
        "POSTGRES_PASSWORD",
    ],
)
def test_secret_field_names_are_recognised(name: str) -> None:
    assert looks_secret_key(name)


@pytest.mark.parametrize(
    "name", ["hostname", "subnet", "description", "ttl", "record_type", "enabled"]
)
def test_ordinary_field_names_are_not_treated_as_secret(name: str) -> None:
    """A denylist that matches everything redacts the whole bundle."""
    assert not looks_secret_key(name)


def test_url_embedded_credentials_are_stripped() -> None:
    """Found by generating a real bundle, not by reading the code.

    ``DATABASE_URL`` ships as ``postgresql+asyncpg://user:password@host``
    and no name-based rule catches it — the variable is called *_URL. The
    userinfo is a credential regardless of what the field is named.
    """
    cleaned, kinds = redact_secrets(
        "DATABASE_URL=postgresql+asyncpg://spatiumddi:hunter2@postgres:5432/db"
    )
    assert "hunter2" not in cleaned
    assert "url-credentials" in kinds
    # Scheme, host, port and path are topology and must survive — the
    # host is pseudonymised separately.
    assert "postgresql+asyncpg://" in cleaned
    assert "@postgres:5432/db" in cleaned


@pytest.mark.parametrize(
    "url", ["redis://redis:6379/0", "http://10.0.0.1:8000", "https://example.com/path"]
)
def test_urls_without_credentials_are_untouched(url: str) -> None:
    assert redact_secrets(url)[0] == url


def test_redaction_is_idempotent() -> None:
    """Redacting already-redacted text must be a no-op.

    It was not: the URL replacement "[REDACTED]:[REDACTED]" matched the
    userinfo pattern that produced it, so a second pass re-fired. The
    safety net then reported a hit on text a collector had already
    cleaned — a false bug report from the one mechanism whose value
    depends on a hit meaning a real one.
    """
    samples = [
        "DATABASE_URL=postgresql+asyncpg://u:p@host:5432/db",
        "token=gAAAAABm1234567890abcdefghij",
        "hash=$2b$12$" + "a" * 53,
    ]
    for raw in samples:
        once, first_kinds = redact_secrets(raw)
        twice, second_kinds = redact_secrets(once)
        assert twice == once, raw
        assert first_kinds and second_kinds == [], raw


@pytest.mark.parametrize("name", ["DNS_AGENT_KEY", "DHCP_AGENT_KEY", "LG_AGENT_KEY"])
def test_agent_preshared_keys_are_recognised_by_name(name: str) -> None:
    """Also found by generating a real bundle. These are raw hex with no
    shape a value-matcher could recognise, so the name is the ONLY thing
    that can catch them — and an ``api_key``-style enumeration of
    suffixes will always be one variant behind the next agent kind."""
    assert looks_secret_key(name)


def test_safety_net_records_what_it_caught() -> None:
    """A net that fires silently hides the collector bug that fed it."""
    report = ScrubReport()
    out = safety_net("config/leaky.json", "k=gAAAAABm1234567890abcdefghij", report)
    assert "gAAAAABm" not in out
    assert report.safety_net_hits and "config/leaky.json" in report.safety_net_hits[0]


# ── Pseudonymisation tier ───────────────────────────────────────────────


def test_ipv4_mapping_is_stable_and_topology_preserving() -> None:
    s = Scrubber(seed="seed")
    a, b, c = s.ipv4("10.1.2.5"), s.ipv4("10.1.2.9"), s.ipv4("10.1.3.5")

    assert a != "10.1.2.5"
    assert s.ipv4("10.1.2.5") == a, "same input must map to the same output"

    # Same real /24 -> same synthetic /24. This is what keeps a bundle
    # readable: "are these hosts on one segment" stays answerable.
    assert a.rsplit(".", 1)[0] == b.rsplit(".", 1)[0]
    assert a.rsplit(".", 1)[0] != c.rsplit(".", 1)[0]

    # Host octet survives, so ".1 is the gateway" / ".255 is broadcast"
    # still reads correctly.
    assert a.endswith(".5") and b.endswith(".9")

    # Synthetic space is unroutable and unmistakable — and inside
    # 240.0.0.0/6, so nothing lands in 255.x where it would read as
    # broadcast address space.
    for value in (a, b, c):
        assert ipaddress.IPv4Address(value) in ipaddress.IPv4Network("240.0.0.0/6")


def test_two_installs_map_the_same_address_differently() -> None:
    """Seeded per install, so a synthetic address cannot be correlated
    back across two organisations' bundles."""
    assert Scrubber(seed="one").ipv4("10.0.0.1") != Scrubber(seed="two").ipv4("10.0.0.1")


@pytest.mark.parametrize("addr", ["127.0.0.1", "0.0.0.0", "169.254.1.1", "224.0.0.251"])
def test_diagnostic_ipv4_addresses_survive(addr: str) -> None:
    """Loopback / unspecified / link-local / multicast identify nobody
    and are load-bearing when reading a log."""
    assert Scrubber(seed="s").ipv4(addr) == addr


@pytest.mark.parametrize("addr", ["::1", "fe80::1", "ff02::1"])
def test_diagnostic_ipv6_addresses_survive(addr: str) -> None:
    assert Scrubber(seed="s").ipv6(addr) == addr


def test_ipv6_groups_by_prefix_but_discards_the_interface_id() -> None:
    """A SLAAC address embeds the MAC (RFC 4291 modified EUI-64), so
    carrying the interface ID through would leak hardware identity
    straight past the MAC scrubber."""
    s = Scrubber(seed="seed")
    a = s.ipv6("2001:db8:1::5")
    b = s.ipv6("2001:db8:1::9")
    c = s.ipv6("2001:db8:2::5")

    assert ipaddress.IPv6Address(a) in ipaddress.IPv6Network("2001:db8::/32")
    prefix = lambda v: str(ipaddress.IPv6Network(f"{v}/64", strict=False))  # noqa: E731
    assert prefix(a) == prefix(b), "same /64 must stay grouped"
    assert prefix(a) != prefix(c)
    # The EUI-64 case: the IID must not survive in any form.
    eui = s.ipv6("2001:db8:1::0200:5eff:fe00:5213")
    assert "5eff" not in eui and "fe00" not in eui


def test_mac_mapping_is_stable_case_insensitive_and_drops_the_oui() -> None:
    s = Scrubber(seed="seed")
    a = s.mac("AA:BB:CC:DD:EE:FF")
    assert s.mac("aa-bb-cc-dd-ee-ff") == a, "separator/case must not fork the mapping"
    # Locally-administered prefix: cannot collide with a real assignment.
    assert a.startswith("02:00:00:")
    # The real OUI names the hardware vendor, which is site-identifying
    # in aggregate.
    assert "aa:bb:cc" not in a.lower()


def test_hostname_mapping_preserves_zone_grouping() -> None:
    s = Scrubber(seed="seed")
    a = s.hostname("a.corp.example.net")
    b = s.hostname("b.corp.example.net")
    c = s.hostname("c.other.example.net")
    d = s.hostname("x.elsewhere.test")

    assert a.endswith(".invalid") and "example" not in a
    # Same zone AND same subdomain -> shared suffix.
    assert a.split(".", 1)[1] == b.split(".", 1)[1]
    # Same zone, different subdomain -> shared registrable label only.
    assert a.split(".")[-2] == c.split(".")[-2]
    assert a.split(".", 1)[1] != c.split(".", 1)[1]
    # Different zone -> nothing shared.
    assert a.split(".")[-2] != d.split(".")[-2]
    # Subdomain depth is preserved: two subdomain labels in, two `n`
    # labels out. The registrable domain collapses to one synthetic
    # label plus `.invalid`, so the total happens to match here — the
    # invariant being pinned is the subdomain count, not the total.
    assert len([p for p in a.split(".") if p.startswith("n")]) == 2
    assert len([p for p in s.hostname("deep.a.b.corp.test").split(".") if p.startswith("n")]) == 3


@pytest.mark.parametrize(
    "token",
    [
        "sqlalchemy.exc.ProgrammingError",
        "pathlib.PosixPath",
        "versions.json",
        "internal-errors.json",
        "named.conf",
        "app.yml",
    ],
)
def test_code_tokens_are_not_mistaken_for_hostnames(token: str) -> None:
    """A traceback is among the most useful things in a bundle, and the
    hostname pattern happily eats it — `sqlalchemy.exc.ProgrammingError`
    is "labels separated by dots ending in letters" too.

    Every rule that spares these is strictly safe: a camel-case final
    label and a non-TLD extension both describe tokens that could not
    resolve anyway, so nothing real stays exposed to buy the
    readability.
    """
    assert Scrubber(seed="s").text(token) == token


@pytest.mark.parametrize(
    "name",
    [
        # These ARE real TLDs (Paraguay, .sh, .zone), so sparing them to
        # tidy up a traceback would leak a genuine hostname.
        "collect.py",
        "deploy.sh",
        "corp.example.zone",
        # An all-caps final label is a shouted hostname, not camel-case
        # code — it must still be pseudonymised.
        "HOST.EXAMPLE.COM",
    ],
)
def test_tokens_that_could_be_real_hostnames_are_still_scrubbed(name: str) -> None:
    assert Scrubber(seed="s").text(name) != name


@pytest.mark.parametrize(
    "name", ["localhost", "5.2.1.10.in-addr.arpa", "1.0.0.0.ip6.arpa", "example.com"]
)
def test_structural_names_are_left_alone(name: str) -> None:
    """Rewriting a reverse-DNS name destroys the only thing that makes a
    PTR log readable, and it identifies nobody."""
    assert Scrubber(seed="s").hostname(name) == name


def test_text_sweep_handles_a_realistic_log_line() -> None:
    s = Scrubber(seed="seed")
    line = (
        "2026-08-22 lease 10.1.2.50 -> host7.corp.example.net "
        "mac aa:bb:cc:dd:ee:ff on subnet 10.1.2.0/24 via 2001:db8:9::1"
    )
    out = s.text(line)
    for leaked in ("10.1.2.50", "corp.example.net", "aa:bb:cc:dd:ee:ff", "2001:db8:9::1"):
        assert leaked not in out, f"{leaked} survived the sweep"
    # Structure that makes the line readable survives.
    assert "2026-08-22 lease" in out
    assert "/24" in out, "CIDR prefix length is topology, not identity"
    assert out.count("->") == 1


def test_cidr_prefix_length_is_preserved() -> None:
    s = Scrubber(seed="seed")
    assert s.text("192.168.4.0/22").endswith("/22")


def test_decode_map_inverts_the_mapping() -> None:
    s = Scrubber(seed="seed")
    synthetic_ip = s.ipv4("10.9.8.7")
    synthetic_host = s.hostname("db.corp.example.net")
    mapping = s.decode_map()
    assert mapping["ipv4"][synthetic_ip] == "10.9.8.7"
    assert mapping["hostname"][synthetic_host] == "db.corp.example.net"
    # Values that were deliberately passed through are not listed as
    # mappings — there is nothing to decode.
    s.ipv4("127.0.0.1")
    assert "127.0.0.1" not in s.decode_map()["ipv4"]


# ── Bundle assembly ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bundle_generates_on_a_non_appliance_install(db_session: AsyncSession) -> None:
    """The appliance-only endpoint 503s here; this one must not.

    Its kubeapi-backed sections are absent, and their absence is
    explained rather than silent — an empty section and an inapplicable
    one are indistinguishable otherwise.
    """
    result = await generate(db_session, scrubbed=True)
    assert result.archive
    assert result.errors == [], result.errors

    with zipfile.ZipFile(BytesIO(result.archive)) as zf:
        names = set(zf.namelist())
        manifest = json.loads(zf.read("manifest.json"))

    assert "manifest.json" in names
    assert "versions.json" in names
    assert any(n.startswith("config/") for n in names)
    assert manifest["scrubbed"] is True
    assert manifest["scrub"]["safety_net_hits"] == []
    # The note explains WHY container logs are missing on this shape.
    assert "containers/_note.txt" in names


@pytest.mark.asyncio
async def test_decode_map_is_never_inside_the_archive(db_session: AsyncSession) -> None:
    """A bundle carrying its own decoder is not scrubbed, it is merely
    inconvenient to read."""
    result = await generate(db_session, scrubbed=True)
    with zipfile.ZipFile(BytesIO(result.archive)) as zf:
        names = zf.namelist()
        blob = b"".join(zf.read(n) for n in names)
    assert not any("decode" in n or "scrub-map" in n for n in names)
    # And no file contains the reverse mapping's contents.
    for synthetic, real in list(result.decode_map["hostname"].items())[:20]:
        assert real.encode() not in blob, f"{real} leaked alongside {synthetic}"


@pytest.mark.asyncio
async def test_manifest_warns_differently_per_mode(db_session: AsyncSession) -> None:
    scrubbed = await generate(db_session, scrubbed=True)
    raw = await generate(db_session, scrubbed=False)

    assert "REVIEW THIS ARCHIVE BEFORE SHARING" in scrubbed.manifest["READ_THIS"]
    assert "NOT SCRUBBED" in raw.manifest["READ_THIS"]
    # The filename itself has to make the difference obvious — an
    # operator picking a file out of ~/Downloads a week later has only
    # the name to go on.
    assert "UNSCRUBBED" in raw.filename
    assert "UNSCRUBBED" not in scrubbed.filename


@pytest.mark.asyncio
async def test_platform_settings_drops_credentials_but_keeps_policy(
    db_session: AsyncSession,
) -> None:
    """Name-matching alone over-redacts: ``password_min_length`` is an
    integer policy knob, and "what is their password policy" is a routine
    support question whose answer is not a secret."""
    result = await generate(db_session, scrubbed=True)
    with zipfile.ZipFile(BytesIO(result.archive)) as zf:
        settings_dump = json.loads(zf.read("config/platform-settings.json"))

    if "_note" in settings_dump:
        pytest.skip("no platform_settings row on a fresh test database")

    for column in settings_dump["_redacted_columns"]:
        assert settings_dump[column] in (None, "[REDACTED]")
    # Textual credential columns must be in the redacted set...
    assert "fingerbank_api_key_encrypted" in settings_dump["_redacted_columns"]
    # ...and numeric/boolean ones must not.
    assert "password_min_length" not in settings_dump["_redacted_columns"]
    assert isinstance(settings_dump["password_min_length"], int)


# ── API gates ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_non_superadmin_is_refused(db_session: AsyncSession, client: AsyncClient) -> None:
    """One archive carries logs, config shape and an audit tail; a
    narrower gate would be a way to read all three."""
    _, token = await _user(db_session, "sbplain", superadmin=False)
    await db_session.commit()
    for path in ("/api/v1/system/support-bundle", "/api/v1/system/support-bundle/preview"):
        resp = await client.post(path, headers={"Authorization": f"Bearer {token}"}, json={})
        assert resp.status_code == 403, (path, resp.text)


@pytest.mark.asyncio
async def test_preview_lists_files_and_scrub_counts(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _user(db_session, "sbprev", superadmin=True)
    await db_session.commit()
    resp = await client.post(
        "/api/v1/system/support-bundle/preview",
        headers={"Authorization": f"Bearer {token}"},
        json={},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["scrubbed"] is True
    assert body["files"], "preview with no files tells the operator nothing"
    assert {"path", "bytes", "truncated"} <= set(body["files"][0])
    assert "REVIEW THIS ARCHIVE BEFORE SHARING" in body["warning"]
    assert "scrub" in body["manifest"]


@pytest.mark.asyncio
async def test_unscrubbed_requires_the_exact_confirmation(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """Not a checkbox. The difference between the two bundles is whether
    real addresses leave the building."""
    _, token = await _user(db_session, "sbraw", superadmin=True)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {token}"}

    missing = await client.post(
        "/api/v1/system/support-bundle", headers=headers, json={"scrubbed": False}
    )
    assert missing.status_code == 400
    assert "confirm_unscrubbed" in missing.text

    wrong = await client.post(
        "/api/v1/system/support-bundle",
        headers=headers,
        json={"scrubbed": False, "confirm_unscrubbed": "yes"},
    )
    assert wrong.status_code == 400

    ok = await client.post(
        "/api/v1/system/support-bundle",
        headers=headers,
        json={
            "scrubbed": False,
            "confirm_unscrubbed": "I understand this bundle is not anonymised",
        },
    )
    assert ok.status_code == 200
    assert "UNSCRUBBED" in ok.headers["content-disposition"]


@pytest.mark.asyncio
async def test_download_returns_a_readable_zip(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, token = await _user(db_session, "sbdl", superadmin=True)
    await db_session.commit()
    resp = await client.post(
        "/api/v1/system/support-bundle",
        headers={"Authorization": f"Bearer {token}"},
        json={},
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(BytesIO(resp.content)) as zf:
        assert zf.testzip() is None
        assert "manifest.json" in zf.namelist()


@pytest.mark.asyncio
async def test_generation_is_audited(db_session: AsyncSession, client: AsyncClient) -> None:
    from sqlalchemy import select

    from app.models.audit import AuditLog

    _, token = await _user(db_session, "sbaudit", superadmin=True)
    await db_session.commit()
    await client.post(
        "/api/v1/system/support-bundle",
        headers={"Authorization": f"Bearer {token}"},
        json={},
    )
    rows = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.resource_type == "support_bundle")
            )
        )
        .scalars()
        .all()
    )
    assert rows and rows[0].action == "export"


@pytest.mark.asyncio
async def test_decode_map_endpoint_is_superadmin_only_and_warns(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    _, plain = await _user(db_session, "sbmapplain", superadmin=False)
    _, admin = await _user(db_session, "sbmapadmin", superadmin=True)
    await db_session.commit()

    denied = await client.post(
        "/api/v1/system/support-bundle/decode-map",
        headers={"Authorization": f"Bearer {plain}"},
    )
    assert denied.status_code == 403

    allowed = await client.post(
        "/api/v1/system/support-bundle/decode-map",
        headers={"Authorization": f"Bearer {admin}"},
    )
    assert allowed.status_code == 200
    body = allowed.json()
    assert "Keep it local" in body["warning"]
    assert set(body["mappings"]) >= {"ipv4", "hostname", "mac"}


@pytest.mark.asyncio
async def test_decode_map_is_stable_across_regenerations(db_session: AsyncSession) -> None:
    """The endpoint regenerates rather than storing the archive. That
    only works because the mapping is deterministic per install — a
    token from yesterday's bundle has to resolve the same way today."""
    first = Scrubber(seed="install-seed")
    second = Scrubber(seed="install-seed")
    assert first.ipv4("10.4.5.6") == second.ipv4("10.4.5.6")
    assert first.hostname("a.b.example.net") == second.hostname("a.b.example.net")
    assert first.mac("aa:bb:cc:11:22:33") == second.mac("aa:bb:cc:11:22:33")


# ── Installer logs (#995 item 1) ──────────────────────────────────────
#
# spatium-install copies its own logs to /var/log/spatiumddi/install/ as
# the last write before it unmounts the target, because until then they
# lived on the live ISO's tmpfs and the rsync excludes /var/log/* — so
# the one artefact explaining how a box was built was the one artefact
# the build threw away. The bundle has to reach into that subdirectory
# explicitly: list_log_sources globs *.log NON-recursively, and it is the
# allowlist behind the Logs tab's path-injection sanitizer.


def _installer_log_dir(tmp_path, monkeypatch):
    from app.services.appliance import diagnostics

    base = tmp_path / "hostlogs"
    (base / "install").mkdir(parents=True)
    (base / "firstboot.log").write_text("host log\n")
    monkeypatch.setattr(diagnostics, "_HOST_LOG_DIR", base)
    return base


def test_installer_logs_are_collected_from_the_subdirectory(tmp_path, monkeypatch):
    from app.services.support_bundle.collect import collect_host_logs

    base = _installer_log_dir(tmp_path, monkeypatch)
    (base / "install" / "spatium-install.log").write_text("[ts] Step: welcome\n")
    (base / "install" / "spatium-install-trace.log").write_text("+ main()\n")

    out = collect_host_logs(Scrubber(enabled=False, seed="s"))
    assert "install/spatium-install.log" in out
    assert "install/spatium-install-trace.log" in out
    assert "Step: welcome" in out["install/spatium-install.log"]
    # The flat host logs still come through — the subdirectory is an
    # addition, not a replacement.
    assert "firstboot.log" in out


def test_installer_logs_are_scrubbed_like_every_other_log(tmp_path, monkeypatch):
    """They are the most identifier-dense text in the bundle: a full bash
    xtrace naming every address, hostname and disk the wizard touched."""
    from app.services.support_bundle.collect import collect_host_logs

    base = _installer_log_dir(tmp_path, monkeypatch)
    (base / "install" / "spatium-install.log").write_text(
        "static ip 192.168.7.42 hostname ns1.corp.example\n"
    )
    out = collect_host_logs(Scrubber(enabled=True, seed="s"))
    body = out["install/spatium-install.log"]
    assert "192.168.7.42" not in body
    assert "ns1.corp.example" not in body


def test_no_installer_directory_is_silence_not_a_note(tmp_path, monkeypatch):
    """Absent on every install that was not made from the ISO — compose,
    plain Kubernetes, an appliance imaged some other way. A note there
    would read as something being wrong."""
    from app.services.support_bundle.collect import collect_host_logs

    _installer_log_dir(tmp_path, monkeypatch)
    (tmp_path / "hostlogs" / "install").rmdir()
    out = collect_host_logs(Scrubber(enabled=False, seed="s"))
    assert not [k for k in out if k.startswith("install/")]


def test_a_subdirectory_under_install_is_skipped(tmp_path, monkeypatch):
    """is_file(), so a stray directory does not raise IsADirectoryError
    and take the whole logs section down with it."""
    from app.services.support_bundle.collect import collect_host_logs

    base = _installer_log_dir(tmp_path, monkeypatch)
    (base / "install" / "nested").mkdir()
    (base / "install" / "spatium-install.log").write_text("ok\n")
    out = collect_host_logs(Scrubber(enabled=False, seed="s"))
    assert "install/spatium-install.log" in out
    assert "install/nested" not in out


def test_installer_logs_survive_an_empty_top_level_log_dir(tmp_path, monkeypatch):
    """The regression the early return caused.

    A box whose host log dir holds only ``install/`` is an install that
    died before firstboot opened its own log — exactly the case item 1
    exists for. The old ordering returned "No host log directory is
    mounted" and dropped the install logs, while the directory it called
    absent was sitting right there.
    """
    from app.services.support_bundle.collect import collect_host_logs

    base = _installer_log_dir(tmp_path, monkeypatch)
    (base / "firstboot.log").unlink()
    (base / "install" / "spatium-install.log").write_text("[ts] Step: welcome\n")

    out = collect_host_logs(Scrubber(enabled=False, seed="s"))
    assert "install/spatium-install.log" in out
    assert "_note.txt" not in out


def test_a_truly_absent_host_log_dir_still_reports_the_note(tmp_path, monkeypatch):
    """Control for the test above — the note must not have been lost."""
    from app.services.appliance import diagnostics
    from app.services.support_bundle.collect import collect_host_logs

    monkeypatch.setattr(diagnostics, "_HOST_LOG_DIR", tmp_path / "nope")
    monkeypatch.setattr(diagnostics, "_FALLBACK_LOG_DIR", tmp_path / "nope")
    out = collect_host_logs(Scrubber(enabled=False, seed="s"))
    assert list(out) == ["_note.txt"]
