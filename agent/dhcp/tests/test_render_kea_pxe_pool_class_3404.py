"""A pool restricted to a PXE rule's class serves that rule's clients (#3404).

A pool's ``class_restriction`` is rendered as the pool's ``client-class``, and
the API accepts a PXE rule's generated class there (#3387 refuses to remove a
rule that a pool names). Since #2731 every PXE class was rendered
``only-in-additional-list``, and Kea evaluates such a class only after it has
picked the pool and the lease (Kea ARM, Client Classification, "Classification
Steps"). At pool selection no client was in the class yet, so the pool served
nobody. Reproduced live on kea-dhcp4 3.0.3: a PXE client of a scope whose only
pool was restricted to its rule's class got no OFFER, and Kea logged
``ALLOC_ENGINE_V4_ALLOC_FAIL_CLASSES`` with the client's classes
``ALL, VENDOR_CLASS_PXEClient:Arch:00007:UNDI:003016, UNKNOWN``.

Each rule now renders as two classes. The selector keeps the rule's name and
test and carries no boot fields: an ordinary class, evaluated before the pool
is picked. The boot class carries the boot fields, tests
``member('<selector>')`` and is ``only-in-additional-list``, and only the bound
scopes' subnets list it, so #2731's scoping holds.
"""

from __future__ import annotations

from typing import Any

from spatium_dhcp_agent.render_kea import render

VENDOR_AND_ARCH = "substring(option[60].hex,0,9) == 'PXEClient' and option[93].hex == 0x0007"

EFI: dict[str, Any] = {
    "name": "pxe-11111111-aaaaaaaa",
    "match_expression": VENDOR_AND_ARCH,
    "next_server": "192.0.2.50",
    "boot_file_name": "ipxe.efi",
    "is_ipxe_chain": False,
}
HTTP: dict[str, Any] = {
    "name": "pxe-11111111-bbbbbbbb",
    "match_expression": (
        "substring(option[60].hex,0,10) == 'HTTPClient' and option[93].hex == 0x0010"
    ),
    "next_server": "192.0.2.50",
    "boot_file_name": "http.efi",
    "is_ipxe_chain": False,
}


def _scope(cidr: str, *, restrict: list[str | None], pxe: list[str]) -> dict[str, Any]:
    """A v4 scope with one dynamic pool per entry of ``restrict`` (a class name,
    or None for an open pool), bound to the classes in ``pxe``."""
    base = cidr.rsplit(".", 1)[0]
    pools = []
    for i, cls in enumerate(restrict):
        pool: dict[str, Any] = {
            "start_ip": f"{base}.{100 + 50 * i}",
            "end_ip": f"{base}.{119 + 50 * i}",
            "pool_type": "dynamic",
        }
        if cls:
            pool["class_restriction"] = cls
        pools.append(pool)
    return {
        "subnet_cidr": cidr,
        "address_family": "ipv4",
        "is_active": True,
        "lease_time": 3600,
        "options": {},
        "pools": pools,
        "statics": [],
        "pxe_class_names": pxe,
    }


def _render(*scopes: dict[str, Any], pxe: list[dict[str, Any]]) -> dict[str, Any]:
    return render(
        {
            "server": {"dhcp_socket_type": "raw"},
            "global_options": {"lease_time": 3600},
            "scopes": list(scopes),
            "pxe_classes": pxe,
        }
    )["Dhcp4"]


def _classes(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["name"]: c for c in doc.get("client-classes", [])}


def _subnet(doc: dict[str, Any], cidr: str) -> dict[str, Any]:
    return next(s for s in doc["subnet4"] if s["subnet"] == cidr)


def test_a_pool_restricted_to_a_pxe_rule_names_a_class_kea_has_before_it_picks_the_pool() -> None:
    doc = _render(_scope("10.0.30.0/24", restrict=[EFI["name"]], pxe=[EFI["name"]]), pxe=[EFI])

    (pool,) = _subnet(doc, "10.0.30.0/24")["pools"]
    assert pool["client-class"] == EFI["name"]
    cls = _classes(doc)[pool["client-class"]]
    # An additional class is evaluated after the pool is picked: such a pool
    # serves nobody.
    assert "only-in-additional-list" not in cls
    assert cls["test"] == VENDOR_AND_ARCH


def test_every_pool_restricted_to_a_pxe_class_is_evaluated_before_pool_selection() -> None:
    doc = _render(
        _scope("10.0.30.0/24", restrict=[EFI["name"], HTTP["name"]], pxe=[EFI["name"], HTTP["name"]]),
        _scope("10.0.31.0/24", restrict=[EFI["name"], None], pxe=[]),
        pxe=[EFI, HTTP],
    )

    classes = _classes(doc)
    restricted = [p["client-class"] for s in doc["subnet4"] for p in s["pools"] if "client-class" in p]
    assert sorted(restricted) == sorted([EFI["name"], HTTP["name"], EFI["name"]])
    for name in restricted:
        assert name in classes, name
        assert not classes[name].get("only-in-additional-list"), classes[name]


def test_the_class_a_pool_names_boots_no_one() -> None:
    """Evaluated for every packet of every subnet, it must not carry a boot field."""
    doc = _render(_scope("10.0.30.0/24", restrict=[EFI["name"]], pxe=[EFI["name"]]), pxe=[EFI])

    assert _classes(doc)[EFI["name"]] == {"name": EFI["name"], "test": VENDOR_AND_ARCH}


def test_the_boot_fields_reach_only_the_scopes_bound_to_the_profile() -> None:
    doc = _render(
        _scope("10.0.30.0/24", restrict=[EFI["name"]], pxe=[EFI["name"]]),
        _scope("10.0.31.0/24", restrict=[None], pxe=[]),
        pxe=[EFI],
    )

    (listed,) = _subnet(doc, "10.0.30.0/24")["evaluate-additional-classes"]
    assert "evaluate-additional-classes" not in _subnet(doc, "10.0.31.0/24")
    assert listed != EFI["name"]
    assert _classes(doc)[listed] == {
        "name": listed,
        "next-server": "192.0.2.50",
        "boot-file-name": "ipxe.efi",
        "test": f"member('{EFI['name']}')",
        "only-in-additional-list": True,
    }
    for cls in doc["client-classes"]:
        if not cls.get("only-in-additional-list"):
            assert "next-server" not in cls and "boot-file-name" not in cls, cls


def test_a_boot_class_is_declared_after_its_selector() -> None:
    """Kea refuses a ``member()`` of a class that is not yet defined."""
    doc = _render(
        _scope("10.0.30.0/24", restrict=[EFI["name"]], pxe=[EFI["name"], HTTP["name"]]),
        pxe=[EFI, HTTP],
    )

    names = [c["name"] for c in doc["client-classes"]]
    for rule in (EFI, HTTP):
        boot = next(
            c["name"]
            for c in doc["client-classes"]
            if c.get("test") == f"member('{rule['name']}')"
        )
        assert names.index(rule["name"]) < names.index(boot)
    # The bound subnet evaluates the boot classes in the order the rules came.
    listed = _subnet(doc, "10.0.30.0/24")["evaluate-additional-classes"]
    assert [_classes(doc)[n]["boot-file-name"] for n in listed] == ["ipxe.efi", "http.efi"]


def test_a_rule_with_no_test_still_matches_every_client_at_pool_selection() -> None:
    """Kea never assigns an ordinary class that has no test, so the selector of
    an "always match" rule tests ``member('ALL')``; its boot class keeps no test,
    which Kea adds for every client of a subnet that lists it."""
    anyone = {**EFI, "match_expression": ""}
    doc = _render(_scope("10.0.30.0/24", restrict=[EFI["name"]], pxe=[EFI["name"]]), pxe=[anyone])

    assert _classes(doc)[EFI["name"]] == {"name": EFI["name"], "test": "member('ALL')"}
    (listed,) = _subnet(doc, "10.0.30.0/24")["evaluate-additional-classes"]
    boot = _classes(doc)[listed]
    assert listed != EFI["name"]
    assert "test" not in boot
    assert boot["only-in-additional-list"] is True
    assert boot["boot-file-name"] == "ipxe.efi"
