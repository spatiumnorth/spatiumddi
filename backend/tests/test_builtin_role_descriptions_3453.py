"""The DNS and DHCP Editor descriptions promise only the reads they grant (#3453).

Both said "read every DNS / DHCP surface" while their holders are refused the
query log, DNS analytics, Top DNS clients, the DNS threat views and the DHCP
activity log: those routes need read on ``server``, which neither role holds.
The grants stay as they are; the prose is held to them here.
"""

from __future__ import annotations

import re

import pytest

from app.main import _BUILTIN_ROLES

_EVERY_SURFACE = re.compile(r"\bevery\s+(?:\w+\s+)?surface\b", re.IGNORECASE)


def _holds_read(perms: list[dict[str, object]], resource_type: str) -> bool:
    return any(
        p["resource_type"] in (resource_type, "*") and p["action"] in ("read", "admin", "*")
        for p in perms
    )


def test_no_role_claims_every_surface_without_a_read_wildcard() -> None:
    offenders = [
        name
        for name, (desc, perms) in _BUILTIN_ROLES.items()
        if _EVERY_SURFACE.search(desc) and not _holds_read(perms, "server")
    ]
    assert not offenders, f"descriptions promise every surface without read on servers: {offenders}"


@pytest.mark.parametrize(
    ("role", "refused"),
    [
        ("DNS Editor", ("query log", "Top DNS clients", "threat")),
        ("DHCP Editor", ("activity log",)),
    ],
)
def test_editor_description_names_what_needs_read_on_servers(
    role: str, refused: tuple[str, ...]
) -> None:
    desc, perms = _BUILTIN_ROLES[role]
    # The premise: these roles do not hold read on servers (#3130 decided
    # Top DNS clients stays outside the DNS Editor on purpose).
    assert not _holds_read(perms, "server")
    flat = " ".join(desc.split())
    assert "read on servers" in flat
    for surface in refused:
        assert surface in flat
