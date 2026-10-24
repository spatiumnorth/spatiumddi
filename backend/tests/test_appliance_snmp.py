"""Unit tests for the appliance SNMP renderer (issue #153).

Pure-Python — the renderer is deterministic over a ``PlatformSettings``
ORM row but doesn't actually touch the DB. We synthesise the row
in-memory and assert on the rendered config bytes.

Covers:

* ``render_snmpd_conf`` shape for v2c (rocommunity per source CIDR,
  v4/v6 distinction, sysContact / sysLocation quoting, agentAddress)
* v3 emits createUser + rouser at the right access level for
  noauth / auth / priv (the three USM security levels)
* Same settings → same bytes (determinism, so ETag math stays stable)
* ``snmp_bundle`` short-circuits to empty when ``snmp_enabled=False``
  but always returns the same key set so consumers can compute hashes
  without None-handling
* Empty community + empty sources both render *something* but not a
  working config — operator should see comments explaining why
"""

from __future__ import annotations

from app.core.crypto import encrypt_str
from app.models.settings import PlatformSettings
from app.services.appliance.snmp import (
    render_snmpd_conf,
    snmp_bundle,
)


def _bare_settings() -> PlatformSettings:
    """Build a minimal PlatformSettings with SNMP off and no users.

    SQLAlchemy default= kwargs fire only on flush, so set every column
    we care about explicitly. The renderer doesn't touch the DB so
    this is purely a struct."""
    s = PlatformSettings(id=1)
    s.snmp_enabled = False
    s.snmp_version = "v2c"
    s.snmp_community_encrypted = None
    s.snmp_v3_users = []
    s.snmp_allowed_sources = []
    s.snmp_sys_contact = ""
    s.snmp_sys_location = ""
    return s


def test_v2c_renders_rocommunity_for_each_source() -> None:
    s = _bare_settings()
    s.snmp_enabled = True
    s.snmp_version = "v2c"
    s.snmp_community_encrypted = encrypt_str("s3cret")
    s.snmp_allowed_sources = ["10.0.0.0/8", "192.168.1.0/24", "fd00::/8"]
    s.snmp_sys_contact = "ops@example.com"
    s.snmp_sys_location = "Datacenter A, Rack 12"

    text = render_snmpd_conf(s)
    assert "rocommunity s3cret 10.0.0.0/8" in text
    assert "rocommunity s3cret 192.168.1.0/24" in text
    # IPv6 source uses the v6-specific directive
    assert "rocommunity6 s3cret fd00::/8" in text
    # sysContact / sysLocation get double-quoted
    assert 'sysContact     "ops@example.com"' in text
    assert 'sysLocation    "Datacenter A, Rack 12"' in text
    # Standard agent listen line
    assert "agentAddress udp:161,udp6:[::1]:161" in text


def test_renders_agentx_master_for_subagents() -> None:
    """Issue #2154 — this renderer REPLACES Debian's stock snmpd.conf, which
    is where ``master agentx`` used to come from. Without it snmpd never
    takes the AgentX master role and ``lldpd -x`` (LLDP → Expose via SNMP)
    has nothing to register LLDP-MIB with: the toggle saves, lldpd runs,
    and lldpRemTable is never served. Emitted for every version and
    whatever the LLDP settings say — it is a root-only local socket."""
    for version in ("v2c", "v3"):
        s = _bare_settings()
        s.snmp_enabled = True
        s.snmp_version = version
        lines = render_snmpd_conf(s).splitlines()
        assert "master agentx" in lines
        assert "agentXSocket /run/agentx/master" in lines
        # Root-only socket + directory: the only subagent is lldpd, whose
        # monitor keeps CAP_DAC_OVERRIDE, so nothing needs group access.
        assert "agentXPerms 0600 0700" in lines
        # The master role is a unix socket, never a TCP listener — no
        # ``tcp:`` agentXSocket that the host firewall would have to open.
        assert not any(ln.startswith("agentXSocket tcp") for ln in lines)


def test_v2c_empty_community_emits_no_rocommunity_lines() -> None:
    s = _bare_settings()
    s.snmp_enabled = True
    s.snmp_version = "v2c"
    s.snmp_allowed_sources = ["10.0.0.0/8"]

    text = render_snmpd_conf(s)
    assert "rocommunity" not in text
    # But the operator gets a comment explaining why
    assert "no community configured" in text.lower()


def test_v2c_empty_sources_emits_no_rocommunity_lines() -> None:
    s = _bare_settings()
    s.snmp_enabled = True
    s.snmp_version = "v2c"
    s.snmp_community_encrypted = encrypt_str("public")
    s.snmp_allowed_sources = []

    text = render_snmpd_conf(s)
    assert "rocommunity public" not in text
    assert "no allowed" in text.lower()


def test_v3_emits_createuser_and_rouser_at_correct_level() -> None:
    s = _bare_settings()
    s.snmp_enabled = True
    s.snmp_version = "v3"
    s.snmp_v3_users = [
        # noAuthNoPriv user
        {
            "username": "noauth_user",
            "auth_protocol": "none",
            "auth_pass_enc": None,
            "priv_protocol": "none",
            "priv_pass_enc": None,
        },
        # auth-only user
        {
            "username": "auth_user",
            "auth_protocol": "SHA",
            "auth_pass_enc": encrypt_str("auth-pass").decode("ascii"),
            "priv_protocol": "none",
            "priv_pass_enc": None,
        },
        # auth + priv user
        {
            "username": "priv_user",
            "auth_protocol": "SHA",
            "auth_pass_enc": encrypt_str("auth-pass-2").decode("ascii"),
            "priv_protocol": "AES",
            "priv_pass_enc": encrypt_str("priv-pass").decode("ascii"),
        },
    ]

    text = render_snmpd_conf(s)
    # noauth user — just a createUser with no protocols + rouser noauth
    assert "createUser noauth_user" in text
    assert "rouser noauth_user noauth .1" in text
    # auth user — createUser with SHA + pass + rouser auth
    assert 'createUser auth_user SHA "auth-pass"' in text
    assert "rouser auth_user auth .1" in text
    # priv user — createUser with both protocols + pass + rouser priv
    assert 'createUser priv_user SHA "auth-pass-2" AES "priv-pass"' in text
    assert "rouser priv_user priv .1" in text


def test_v3_empty_users_emits_no_createuser_lines() -> None:
    s = _bare_settings()
    s.snmp_enabled = True
    s.snmp_version = "v3"
    s.snmp_v3_users = []

    text = render_snmpd_conf(s)
    assert "createUser" not in text
    assert "no users configured" in text.lower()


def test_renderer_is_deterministic() -> None:
    """Same inputs → same bytes. Critical because the agent's
    config-hash idempotency check depends on byte-stable output."""
    s = _bare_settings()
    s.snmp_enabled = True
    s.snmp_version = "v2c"
    s.snmp_community_encrypted = encrypt_str("public")
    s.snmp_allowed_sources = ["10.0.0.0/8", "192.168.0.0/16"]
    s.snmp_sys_contact = "ops@example.com"

    a = render_snmpd_conf(s)
    b = render_snmpd_conf(s)
    assert a == b


def test_snmp_bundle_short_circuits_when_disabled() -> None:
    s = _bare_settings()
    s.snmp_enabled = False
    s.snmp_version = "v2c"
    s.snmp_community_encrypted = encrypt_str("ignored")

    bundle = snmp_bundle(s)
    assert bundle == {"enabled": False, "config_hash": "", "snmpd_conf": ""}


def test_snmp_bundle_has_stable_keys() -> None:
    """Both enabled and disabled paths return the same key set so
    downstream consumers (agent comparator, ConfigBundle TypedDict)
    don't need to None-guard."""
    on = _bare_settings()
    on.snmp_enabled = True
    on.snmp_version = "v2c"
    on.snmp_community_encrypted = encrypt_str("on")
    on.snmp_allowed_sources = ["10.0.0.0/8"]

    off = _bare_settings()

    on_bundle = snmp_bundle(on)
    off_bundle = snmp_bundle(off)
    assert set(on_bundle.keys()) == set(off_bundle.keys())
    assert on_bundle["enabled"] is True
    assert off_bundle["enabled"] is False
    # Hash is 64 hex chars when enabled, empty when not
    assert len(on_bundle["config_hash"]) == 64
    assert off_bundle["config_hash"] == ""


def test_sys_contact_with_quote_is_escaped() -> None:
    """Defensive — the quote routine has to escape ``"`` to avoid
    blowing up snmpd's parser when an operator pastes an awkward
    contact string."""
    s = _bare_settings()
    s.snmp_enabled = True
    s.snmp_version = "v2c"
    s.snmp_community_encrypted = encrypt_str("c")
    s.snmp_allowed_sources = ["10.0.0.0/8"]
    s.snmp_sys_contact = 'someone "with quotes"'

    text = render_snmpd_conf(s)
    # The quoted form should escape the embedded quotes; snmpd reads
    # a single double-quoted string.
    assert r'"someone \"with quotes\""' in text


def test_disabled_master_toggle_renders_no_config() -> None:
    """The bundle path is what real consumers use; the renderer is
    a stable pure function. When the master toggle is off, the
    bundle's snmpd_conf body is empty (the runner's ``disabled``
    branch stubs the file out)."""
    s = _bare_settings()
    s.snmp_enabled = False
    s.snmp_version = "v2c"
    s.snmp_community_encrypted = encrypt_str("ignored")
    s.snmp_allowed_sources = ["10.0.0.0/8"]

    bundle = snmp_bundle(s)
    assert bundle["snmpd_conf"] == ""


# ── Undecryptable v3 passphrases must not downgrade the user ─────────
#
# #781 flagged this as an unverified claim while reviewing the secret
# rewrap; it is real. ``_decrypt_v3_pass`` returns ``None`` for both
# "absent" and "undecryptable", and the renderer's level ladder gated on
# ``auth_proto != "none" and auth_pass``. A user configured for authPriv
# whose passphrase could not be decrypted therefore fell all the way
# through to ``rouser <name> noauth`` — an unauthenticated read-only
# SNMPv3 user reachable by anyone the firewall lets in.
#
# That is a silent security downgrade, and strictly worse than an
# outage: nothing fails, so nobody looks. The trigger is any key
# mismatch — a rotated SECRET_KEY, or a cross-install restore whose
# rewrap did not cover these JSONB-embedded fields (which it did not,
# before #796).


def _undecryptable() -> str:
    """A syntactically valid Fernet token this install cannot decrypt.

    Encrypted under a different key, so ``decrypt_str`` raises
    ``InvalidToken`` exactly as it would after a key rotation — rather
    than raising some other error a garbage string would produce.
    """
    import base64
    import os

    from cryptography.fernet import Fernet

    other = Fernet(base64.urlsafe_b64encode(os.urandom(32)))
    return other.encrypt(b"the-real-passphrase").decode("ascii")


def test_v3_user_with_undecryptable_auth_pass_is_omitted_not_downgraded() -> None:
    s = _bare_settings()
    s.snmp_enabled = True
    s.snmp_version = "v3"
    s.snmp_v3_users = [
        {
            "username": "authpriv_user",
            "auth_protocol": "SHA",
            "auth_pass_enc": _undecryptable(),
            "priv_protocol": "AES",
            "priv_pass_enc": encrypt_str("priv-pass").decode("ascii"),
        }
    ]

    text = render_snmpd_conf(s)

    # The critical assertion: the user is NOT published unauthenticated.
    assert "rouser authpriv_user noauth" not in text
    # ...and not published at all.
    assert "createUser authpriv_user" not in text
    assert "rouser authpriv_user" not in text
    # The config says why, so an operator reading snmpd.conf isn't left
    # wondering where their user went.
    assert "OMITTED" in text
    assert "authpriv_user" in text


def test_v3_user_with_undecryptable_priv_pass_is_omitted_not_left_unencrypted() -> None:
    """One rung down the ladder: auth decrypts, privacy doesn't.

    Publishing at ``auth`` would authenticate the poller but leave every
    response in cleartext on the wire — not what an operator who
    configured authPriv asked for.
    """
    s = _bare_settings()
    s.snmp_enabled = True
    s.snmp_version = "v3"
    s.snmp_v3_users = [
        {
            "username": "halfbroken_user",
            "auth_protocol": "SHA",
            "auth_pass_enc": encrypt_str("auth-pass").decode("ascii"),
            "priv_protocol": "AES",
            "priv_pass_enc": _undecryptable(),
        }
    ]

    text = render_snmpd_conf(s)

    assert "rouser halfbroken_user auth" not in text
    assert "rouser halfbroken_user noauth" not in text
    assert "createUser halfbroken_user" not in text
    assert "OMITTED" in text


def test_a_deliberate_noauth_user_still_renders() -> None:
    """The guard keys off ``auth_protocol``, not off a missing passphrase.

    An operator who genuinely configured noAuthNoPriv has no passphrase
    to decrypt, and must not be caught by the new check.
    """
    s = _bare_settings()
    s.snmp_enabled = True
    s.snmp_version = "v3"
    s.snmp_v3_users = [
        {
            "username": "intentional_noauth",
            "auth_protocol": "none",
            "auth_pass_enc": None,
            "priv_protocol": "none",
            "priv_pass_enc": None,
        }
    ]

    text = render_snmpd_conf(s)

    assert "createUser intentional_noauth" in text
    assert "rouser intentional_noauth noauth .1" in text
    assert "OMITTED" not in text


def test_a_broken_user_does_not_suppress_a_healthy_one() -> None:
    s = _bare_settings()
    s.snmp_enabled = True
    s.snmp_version = "v3"
    s.snmp_v3_users = [
        {
            "username": "broken_user",
            "auth_protocol": "SHA",
            "auth_pass_enc": _undecryptable(),
            "priv_protocol": "none",
            "priv_pass_enc": None,
        },
        {
            "username": "healthy_user",
            "auth_protocol": "SHA",
            "auth_pass_enc": encrypt_str("good-pass").decode("ascii"),
            "priv_protocol": "none",
            "priv_pass_enc": None,
        },
    ]

    text = render_snmpd_conf(s)

    assert "rouser broken_user" not in text
    assert 'createUser healthy_user SHA "good-pass"' in text
    assert "rouser healthy_user auth .1" in text


# ── snmpd.conf injection via the v3 username ─────────────────────────
#
# Raised on the #802 review as token-splitting; it is worse than that.
# snmpd.conf is whitespace-delimited and does not quote the username
# token, so a username carrying a NEWLINE ends the directive and starts
# a new one. ``ops\nrwuser evil .1`` renders as:
#
#     createUser ops
#     rwuser evil .1 SHA "pass"
#
# i.e. an operator who can edit SNMP settings can inject arbitrary
# snmpd.conf directives, including a READ-WRITE user. Superadmin-only,
# so not remote-unauthenticated — but it is still a privilege escalation
# from "edits a settings form" to "writes the daemon's config".
#
# Fixed in two places on purpose: the settings router rejects it at the
# API boundary (the right place, and where the operator sees the error),
# and the renderer re-checks because rows written before that validator
# existed are still in the database and this renderer is the last thing
# between stored state and the file snmpd loads.


def test_v3_username_with_a_newline_cannot_inject_a_directive() -> None:
    s = _bare_settings()
    s.snmp_enabled = True
    s.snmp_version = "v3"
    s.snmp_v3_users = [
        {
            "username": "ops\nrwuser evil .1",
            "auth_protocol": "SHA",
            "auth_pass_enc": encrypt_str("pass").decode("ascii"),
            "priv_protocol": "none",
            "priv_pass_enc": None,
        }
    ]

    text = render_snmpd_conf(s)

    # The injected directive must not appear anywhere.
    assert "rwuser" not in text
    assert "evil" not in text
    # And the user is not published under any name.
    assert "createUser ops" not in text
    assert "OMITTED" in text


def test_v3_username_with_internal_whitespace_is_omitted() -> None:
    """Not an injection, but still unrenderable: the extra token would
    be read as the auth protocol."""
    s = _bare_settings()
    s.snmp_enabled = True
    s.snmp_version = "v3"
    s.snmp_v3_users = [
        {
            "username": "ops ro",
            "auth_protocol": "SHA",
            "auth_pass_enc": encrypt_str("pass").decode("ascii"),
            "priv_protocol": "none",
            "priv_pass_enc": None,
        }
    ]

    text = render_snmpd_conf(s)

    assert "createUser ops ro" not in text
    assert "rouser ops ro" not in text
    assert "OMITTED" in text


def test_a_normal_username_is_unaffected_by_the_guard() -> None:
    """Guard against over-correcting — the usual shapes must still render."""
    s = _bare_settings()
    s.snmp_enabled = True
    s.snmp_version = "v3"
    s.snmp_v3_users = [
        {
            "username": "monitoring-ro_1",
            "auth_protocol": "SHA",
            "auth_pass_enc": encrypt_str("pass").decode("ascii"),
            "priv_protocol": "none",
            "priv_pass_enc": None,
        }
    ]

    text = render_snmpd_conf(s)

    assert 'createUser monitoring-ro_1 SHA "pass"' in text
    assert "rouser monitoring-ro_1 auth .1" in text
    assert "OMITTED" not in text


# ── API-boundary rejection of the same shapes ────────────────────────
#
# The renderer guard above is the backstop for rows already in the
# database. This is the primary fix: the operator's own PUT is the error
# site, so they find out at the form rather than via a daemon that
# quietly reloaded a config they didn't write.


def test_settings_validator_rejects_a_newline_username() -> None:
    import pytest
    from pydantic import ValidationError

    from app.api.v1.settings.router import SNMPV3UserUpdate

    with pytest.raises(ValidationError) as exc:
        SNMPV3UserUpdate(username="ops\nrwuser evil .1")
    assert "whitespace or control characters" in str(exc.value)


def test_settings_validator_rejects_internal_whitespace() -> None:
    import pytest
    from pydantic import ValidationError

    from app.api.v1.settings.router import SNMPV3UserUpdate

    with pytest.raises(ValidationError):
        SNMPV3UserUpdate(username="ops ro")


def test_settings_validator_still_trims_and_accepts_normal_names() -> None:
    """Surrounding whitespace is trimmed, as before — only INTERNAL
    whitespace is a problem, and the trim must not be mistaken for it."""
    from app.api.v1.settings.router import SNMPV3UserUpdate

    assert SNMPV3UserUpdate(username="  monitoring-ro_1  ").username == "monitoring-ro_1"
