"""BIND9 agent DNSSEC rendering + status parsing (issue #49).

Exercises ``Bind9Driver.render`` against bundles shaped like
``app.services.dns.agent_config.build_config_bundle`` emits — a signed
zone gets ``dnssec-policy`` + ``inline-signing yes`` in its stanza and a
referenced custom policy renders a top-level ``dnssec-policy { … }``
block. Also covers the pure ``rndc dnssec -status`` parser + the KSK
keyfile classifier.
"""

from __future__ import annotations

from pathlib import Path

from spatium_dns_agent.drivers.bind9 import (
    Bind9Driver,
    _keyfile_is_ksk,
    _parse_dnssec_status,
    _render_dnssec_policies,
)


def _zone(
    name: str, *, dnssec_enabled: bool = False, policy: str | None = None
) -> dict:
    return {
        "id": name,
        "name": name,
        "type": "primary",
        "ttl": 3600,
        "forwarders": [],
        "forward_only": True,
        "view_name": None,
        "records": [],
        "dnssec_enabled": dnssec_enabled,
        "dnssec_policy_name": policy,
    }


def test_signed_zone_default_policy(tmp_path: Path) -> None:
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render({"options": {}, "zones": [_zone("ex.com.", dnssec_enabled=True)]})
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()
    assert 'dnssec-policy "default";' in conf
    assert "inline-signing yes;" in conf
    assert 'key-directory "/var/cache/bind/keys";' in conf


def test_unsigned_zone_no_signing(tmp_path: Path) -> None:
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render({"options": {}, "zones": [_zone("ex.com.", dnssec_enabled=False)]})
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()
    assert "inline-signing" not in conf
    # The bare ``dnssec-policy "name";`` zone clause is absent; key-directory
    # is always present (harmless when no zone is signed).
    assert 'dnssec-policy "' not in conf


def test_custom_policy_block_rendered(tmp_path: Path) -> None:
    drv = Bind9Driver(state_dir=tmp_path)
    drv.render(
        {
            "options": {},
            "zones": [_zone("ex.com.", dnssec_enabled=True, policy="strong")],
            "dnssec_policies": [
                {
                    "name": "strong",
                    "algorithm": "ed25519",
                    "ksk_lifetime_days": 0,
                    "zsk_lifetime_days": 30,
                    "nsec3": True,
                    "nsec3_iterations": 0,
                    "nsec3_salt_length": 0,
                    "nsec3_optout": False,
                }
            ],
        }
    )
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()
    assert 'dnssec-policy "strong" {' in conf
    assert "zsk lifetime 30d algorithm ed25519;" in conf
    assert "nsec3param iterations 0 optout no salt-length 0;" in conf
    assert 'dnssec-policy "strong";' in conf


def test_render_dnssec_policies_skips_default() -> None:
    out = _render_dnssec_policies([{"name": "default", "algorithm": "ecdsap256sha256"}])
    assert out == ""


def test_parse_dnssec_status() -> None:
    sample = """\
dnssec-policy: default
current time: Thu May 29 21:00:00 2026

key: 12345 (ECDSAP256SHA256), KSK
  published:      yes - since Thu May 29 20:00:00 2026
  key signing:    yes - since Thu May 29 20:00:00 2026

key: 23456 (ECDSAP256SHA256), ZSK
  published:      yes - since Thu May 29 20:00:00 2026
  zone signing:   no
"""
    keys = _parse_dnssec_status(sample)
    assert len(keys) == 2
    ksk = next(k for k in keys if k["key_type"] == "ksk")
    zsk = next(k for k in keys if k["key_type"] == "zsk")
    assert ksk["key_tag"] == 12345
    assert ksk["algorithm"] == 13
    assert ksk["state"] == "active"  # "key signing: yes"
    assert zsk["key_tag"] == 23456
    assert zsk["state"] == "published"  # "zone signing: no"


def test_keyfile_is_ksk(tmp_path: Path) -> None:
    ksk = tmp_path / "Kex.com.+013+12345.key"
    ksk.write_text("; comment\nex.com. IN DNSKEY 257 3 13 AAAA...\n")
    zsk = tmp_path / "Kex.com.+013+23456.key"
    zsk.write_text("ex.com. IN DNSKEY 256 3 13 BBBB...\n")
    assert _keyfile_is_ksk(str(ksk)) is True
    assert _keyfile_is_ksk(str(zsk)) is False


def test_nonzero_nsec3_iterations_render_as_zero() -> None:
    """BIND 9.20 rejects the whole named.conf over iterations > 0 (#3153)."""
    out = _render_dnssec_policies(
        [{"name": "old", "nsec3": True, "nsec3_iterations": 151, "nsec3_salt_length": 8}]
    )
    assert "nsec3param iterations 0 optout no salt-length 8;" in out
    assert "151" not in out
