"""DNSSEC trust anchors reach named.conf (#2266).

``DNSTrustAnchor`` rows were stored and listed but never shipped or rendered,
so ``dnssec-validation yes`` validated nothing. Assertions are on the rendered
config, not the bundle.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from spatium_dns_agent.drivers.bind9 import Bind9Driver

ROOT_KSK = (
    "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWX"
    "gnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/"
    "EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzu"
    "DWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU="
)


def _bundle(**opts: Any) -> dict[str, Any]:
    options: dict[str, Any] = {
        "recursion_enabled": True,
        "allow_query": ["any"],
        "dnssec_validation": "yes",
    }
    options.update(opts)
    return {"options": options, "tsig_keys": [], "zones": []}


def _conf(tmp_path: Path, bundle: dict[str, Any]) -> str:
    Bind9Driver(state_dir=tmp_path).render(bundle)
    return (tmp_path / "rendered.new" / "named.conf").read_text()


def test_anchor_renders_as_trust_anchors_statement(tmp_path: Path) -> None:
    conf = _conf(
        tmp_path,
        _bundle(
            trust_anchors=[
                {
                    "zone_name": ".",
                    "algorithm": 8,
                    "key_tag": 20326,
                    "public_key": ROOT_KSK,
                    "is_initial_key": False,
                },
                {
                    "zone_name": "corp.example",
                    "algorithm": 13,
                    "key_tag": 1,
                    "public_key": "AAAA",
                    "is_initial_key": True,
                },
            ]
        ),
    )
    assert f'trust-anchors {{\n    "." static-key 257 3 8 "{ROOT_KSK}";\n' in conf
    assert '    "corp.example" initial-key 257 3 13 "AAAA";\n};\n' in conf


def test_no_anchors_is_byte_identical(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    without = _conf(tmp_path / "a", _bundle())
    empty = _conf(tmp_path / "b", _bundle(trust_anchors=[]))
    assert "trust-anchors" not in without
    assert without == empty


def test_malformed_anchor_is_skipped_not_rendered(tmp_path: Path) -> None:
    conf = _conf(
        tmp_path,
        _bundle(
            trust_anchors=[
                {"zone_name": 'x"; }; evil {', "algorithm": 8, "public_key": "AAAA"},
                {"zone_name": "ok.example", "algorithm": 8, "public_key": 'AA"; };'},
                {"zone_name": "good.example", "algorithm": 8, "public_key": "AAAA"},
            ]
        ),
    )
    assert "evil" not in conf
    assert conf.count("static-key") + conf.count("initial-key") == 1
    assert '"good.example"' in conf
