"""The BIND9 key file only ever holds well-formed ``key {}`` stanzas.

``secret "…";`` and ``key "…"`` are interpolated verbatim, so a stored secret
that is not one base64 string (a row written before the control plane checked
it) could end the statement early and put arbitrary text in a file named
includes. Such a key is left out of the file, and out of every grant and
include that would name it, with a warning; the other keys are untouched.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from spatium_dns_agent.drivers.bind9 import Bind9Driver, _tsig_key_problem

_GOOD = {"name": "spatium-default", "secret": "c2VjcmV0c2VjcmV0", "algorithm": "hmac-sha256"}
_OTHER = {"name": "ops-xfer.", "secret": "b3BzLXhmZXI=", "algorithm": "hmac-sha256"}
_INJECTED = {
    "name": "bad-key",
    "secret": 'AAAA"; }; key "evil" { algorithm hmac-sha256; secret "QUFBQQ==',
    "algorithm": "hmac-sha256",
}


def _bundle(keys: list[dict[str, Any]], **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "options": {
            "forwarders": [],
            "recursion_enabled": False,
            "allow_query": ["any"],
            "dnssec_validation": "auto",
            "allow_transfer": ["none"],
        },
        "tsig_keys": keys,
        "zones": [],
    }
    base.update(over)
    return base


def _render(tmp_path: Path, bundle: dict[str, Any]) -> tuple[str, str]:
    Bind9Driver(state_dir=tmp_path).render(bundle)
    conf = (tmp_path / "rendered.new" / "named.conf").read_text()
    key_file = tmp_path / "rendered.new" / "tsig" / "ddns.key"
    return conf, key_file.read_text() if key_file.exists() else ""


def _stanzas(text: str) -> list[str]:
    return re.findall(
        r'^key "[^"]+" \{ algorithm [a-z0-9-]+; secret "[A-Za-z0-9+/=]+"; \};$', text, flags=re.MULTILINE
    )


def test_a_secret_that_breaks_the_stanza_is_not_written(tmp_path: Path) -> None:
    conf, keys = _render(tmp_path, _bundle([_GOOD, _INJECTED, _OTHER]))
    assert "evil" not in keys
    assert "bad-key" not in keys
    # Every line in the file is one complete, well-formed stanza.
    assert _stanzas(keys) == keys.splitlines()
    assert len(keys.splitlines()) == 2
    # Nothing in named.conf names the skipped key either.
    assert "bad-key" not in conf
    assert 'key "ops-xfer.";' in conf


@pytest.mark.parametrize(
    "secret",
    [
        "not base64!",
        "c2VjcmV0 c2VjcmV0",
        "c2VjcmV0\nc2VjcmV0",
        "c2VjcmV",  # bad padding
        "====",
        "",
        'abc"',
        "abc;",
        "{abc}",
    ],
)
def test_malformed_secrets_are_refused(secret: str) -> None:
    assert _tsig_key_problem({**_GOOD, "secret": secret}) == "secret"


@pytest.mark.parametrize("name", ['a"b', "a b", "a;b", "a{b", "", "a\nb"])
def test_unsafe_names_are_refused(name: str) -> None:
    assert _tsig_key_problem({**_GOOD, "name": name}) == "name"


def test_unsafe_algorithm_is_refused() -> None:
    assert _tsig_key_problem({**_GOOD, "algorithm": "hmac-sha256; }"}) == "algorithm"


@pytest.mark.parametrize(
    "key", [_GOOD, _OTHER, {"name": "spatium_xfr_inside", "secret": "QUFBQQ=="}]
)
def test_well_formed_keys_pass(key: dict[str, Any]) -> None:
    assert _tsig_key_problem(key) is None


def test_well_formed_keys_render_unchanged(tmp_path: Path) -> None:
    _conf, keys = _render(tmp_path, _bundle([_GOOD, _OTHER]))
    assert keys == (
        'key "spatium-default" { algorithm hmac-sha256; secret "c2VjcmV0c2VjcmV0"; };\n'
        'key "ops-xfer." { algorithm hmac-sha256; secret "b3BzLXhmZXI="; };\n'
    )


def test_write_key_file_refuses_an_unchecked_key_itself(tmp_path: Path) -> None:
    """The writer re-checks rather than trusting its caller."""
    Bind9Driver(state_dir=tmp_path)._write_key_file("x.key", [_GOOD, _INJECTED])
    text = (tmp_path / "rendered.new" / "tsig" / "x.key").read_text()
    assert "evil" not in text
    assert _stanzas(text) == text.splitlines()
