"""A pool restricted to a PXE rule's class serves that rule's clients (#3404).

The config preview renders a pool's ``class_restriction`` as the pool's Kea
``client-class``, and the API accepts a PXE rule's generated class there
(``_check_class_family``; #3387 refuses to remove a rule that a pool names).
Since #2731 every PXE class was rendered ``only-in-additional-list``, and Kea
evaluates such a class only after it has picked the pool and the lease, so a
pool restricted to it served nobody (reproduced live on kea-dhcp4 3.0.3: no
OFFER, ``ALLOC_ENGINE_V4_ALLOC_FAIL_CLASSES``).

Each rule now renders as a selector (its own name and test, no boot fields, an
ordinary class) and a boot class (the boot fields, ``member('<selector>')``,
``only-in-additional-list``), and the bound scopes' subnets list the boot
classes. The agent's renderer does the same
(``agent/dhcp/tests/test_render_kea_pxe_pool_class_3404.py``). The boot class's
name is reserved like the other generated names, and a pool still cannot be
restricted to it.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from app.drivers.dhcp.base import ConfigBundle, PoolDef, PXEClassDef, ScopeDef, ServerOptionsDef
from app.drivers.dhcp.kea import KeaDriver
from app.services.dhcp.class_refs import is_builtin_or_generated, reserved_name_reason

VENDOR_AND_ARCH = "substring(option[60].hex,0,9) == 'PXEClient' and option[93].hex == 0x0007"
EFI = PXEClassDef(
    name="pxe-11111111-aaaaaaaa",
    match_expression=VENDOR_AND_ARCH,
    next_server="192.0.2.50",
    boot_file_name="ipxe.efi",
)
HTTP = PXEClassDef(
    name="pxe-11111111-bbbbbbbb",
    match_expression="substring(option[60].hex,0,10) == 'HTTPClient' and option[93].hex == 0x0010",
    next_server="192.0.2.50",
    boot_file_name="http.efi",
)


def _scope(cidr: str, *, restrict: list[str | None], pxe: tuple[str, ...]) -> ScopeDef:
    base = cidr.rsplit(".", 1)[0]
    pools = tuple(
        PoolDef(
            start_ip=f"{base}.{100 + 50 * i}",
            end_ip=f"{base}.{119 + 50 * i}",
            class_restriction=cls,
        )
        for i, cls in enumerate(restrict)
    )
    return ScopeDef(subnet_cidr=cidr, pools=pools, pxe_class_names=pxe)


def _render(*scopes: ScopeDef, pxe: tuple[PXEClassDef, ...]) -> dict[str, Any]:
    bundle = ConfigBundle(
        server_id="00000000-0000-0000-0000-000000000000",
        server_name="kea-pxe-pool-test",
        driver="kea",
        roles=(),
        options=ServerOptionsDef(options={}, lease_time=3600),
        scopes=scopes,
        client_classes=(),
        generated_at=datetime.now(UTC),
        pxe_classes=pxe,
    )
    return json.loads(KeaDriver().render_config(bundle))["Dhcp4"]


def _classes(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["name"]: c for c in doc.get("client-classes", [])}


def _subnet(doc: dict[str, Any], cidr: str) -> dict[str, Any]:
    return next(s for s in doc["subnet4"] if s["subnet"] == cidr)


def test_a_pool_restricted_to_a_pxe_rule_names_a_class_kea_has_before_it_picks_the_pool() -> None:
    doc = _render(_scope("10.0.30.0/24", restrict=[EFI.name], pxe=(EFI.name,)), pxe=(EFI,))

    (pool,) = _subnet(doc, "10.0.30.0/24")["pools"]
    assert pool["client-class"] == EFI.name
    cls = _classes(doc)[pool["client-class"]]
    # An additional class is evaluated after the pool is picked: such a pool
    # serves nobody.
    assert "only-in-additional-list" not in cls
    assert cls["test"] == VENDOR_AND_ARCH


def test_every_pool_restricted_to_a_pxe_class_is_evaluated_before_pool_selection() -> None:
    doc = _render(
        _scope("10.0.30.0/24", restrict=[EFI.name, HTTP.name], pxe=(EFI.name, HTTP.name)),
        _scope("10.0.31.0/24", restrict=[EFI.name, None], pxe=()),
        pxe=(EFI, HTTP),
    )

    classes = _classes(doc)
    restricted = [
        p["client-class"] for s in doc["subnet4"] for p in s["pools"] if "client-class" in p
    ]
    assert sorted(restricted) == sorted([EFI.name, HTTP.name, EFI.name])
    for name in restricted:
        assert name in classes, name
        assert not classes[name].get("only-in-additional-list"), classes[name]


def test_the_class_a_pool_names_boots_no_one() -> None:
    """Evaluated for every packet of every subnet, it must not carry a boot field."""
    doc = _render(_scope("10.0.30.0/24", restrict=[EFI.name], pxe=(EFI.name,)), pxe=(EFI,))

    assert _classes(doc)[EFI.name] == {"name": EFI.name, "test": VENDOR_AND_ARCH}


def test_the_boot_fields_reach_only_the_scopes_bound_to_the_profile() -> None:
    doc = _render(
        _scope("10.0.30.0/24", restrict=[EFI.name], pxe=(EFI.name,)),
        _scope("10.0.31.0/24", restrict=[None], pxe=()),
        pxe=(EFI,),
    )

    (listed,) = _subnet(doc, "10.0.30.0/24")["evaluate-additional-classes"]
    assert "evaluate-additional-classes" not in _subnet(doc, "10.0.31.0/24")
    assert listed != EFI.name
    assert _classes(doc)[listed] == {
        "name": listed,
        "next-server": "192.0.2.50",
        "boot-file-name": "ipxe.efi",
        "test": f"member('{EFI.name}')",
        "only-in-additional-list": True,
    }
    for cls in doc["client-classes"]:
        if not cls.get("only-in-additional-list"):
            assert "next-server" not in cls and "boot-file-name" not in cls, cls


def test_a_boot_class_is_declared_after_its_selector() -> None:
    """Kea refuses a ``member()`` of a class that is not yet defined."""
    doc = _render(
        _scope("10.0.30.0/24", restrict=[EFI.name], pxe=(EFI.name, HTTP.name)),
        pxe=(EFI, HTTP),
    )

    names = [c["name"] for c in doc["client-classes"]]
    for rule in (EFI, HTTP):
        boot = next(
            c["name"] for c in doc["client-classes"] if c.get("test") == f"member('{rule.name}')"
        )
        assert names.index(rule.name) < names.index(boot)
    listed = _subnet(doc, "10.0.30.0/24")["evaluate-additional-classes"]
    assert [_classes(doc)[n]["boot-file-name"] for n in listed] == ["ipxe.efi", "http.efi"]


def test_a_rule_with_no_test_still_matches_every_client_at_pool_selection() -> None:
    """Kea never assigns an ordinary class that has no test, so the selector of
    an "always match" rule tests ``member('ALL')``; its boot class keeps no test,
    which Kea adds for every client of a subnet that lists it."""
    anyone = PXEClassDef(
        name=EFI.name, match_expression="", next_server="192.0.2.50", boot_file_name="ipxe.efi"
    )
    doc = _render(_scope("10.0.30.0/24", restrict=[EFI.name], pxe=(EFI.name,)), pxe=(anyone,))

    assert _classes(doc)[EFI.name] == {"name": EFI.name, "test": "member('ALL')"}
    (listed,) = _subnet(doc, "10.0.30.0/24")["evaluate-additional-classes"]
    boot = _classes(doc)[listed]
    assert listed != EFI.name
    assert "test" not in boot
    assert boot["only-in-additional-list"] is True
    assert boot["boot-file-name"] == "ipxe.efi"


def test_an_operator_class_cannot_take_the_name_of_a_rule_s_boot_class() -> None:
    """A second class of that name makes Kea reject the whole config, and the
    importers would bring one in from a config this product rendered."""
    assert reserved_name_reason("pxe-11111111-aaaaaaaa-boot") is not None

    # ...which is the name the renderer gives the rule's boot class.
    doc = _render(_scope("10.0.30.0/24", restrict=[None], pxe=(EFI.name,)), pxe=(EFI,))
    assert _subnet(doc, "10.0.30.0/24")["evaluate-additional-classes"] == [
        "pxe-11111111-aaaaaaaa-boot"
    ]


def test_a_pool_cannot_be_restricted_to_a_rule_s_boot_class() -> None:
    """Kea evaluates the boot class only after it has picked the pool, so the
    pool would serve no one: the API keeps refusing it (``_check_class_family``)."""
    assert is_builtin_or_generated(EFI.name)
    assert not is_builtin_or_generated("pxe-11111111-aaaaaaaa-boot")
