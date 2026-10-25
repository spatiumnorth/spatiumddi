"""A PXE profile boots the scopes it is bound to, and no other (#2731).

The agent rendered every PXE class into the global ``client-classes``, and
Kea evaluates a global class for every packet it serves: the PXE clients of
every scope on the server were offered one scope's boot server and boot
file. The control plane now sends each scope's own classes
(``pxe_class_names``). The renderer marks the classes
``only-in-additional-list`` and lists them on their scopes' subnets only
(``evaluate-additional-classes``), so Kea evaluates them there and nowhere
else.

Measured on kea-dhcp4 3.0.3, not assumed: such a class's ``next-server`` and
``boot-file-name`` still reach the OFFER, a subnet that lists nothing offers
neither, a class with no ``test`` is added for every client of a subnet that
lists it, and the 2.x spellings (``only-if-required`` /
``require-client-classes``) still load but log a deprecation warning, which
is why the 3.0 names are rendered.
"""

from __future__ import annotations

from typing import Any

from spatium_dhcp_agent.render_kea import render

PXE: dict[str, Any] = {
    "name": "pxe-a",
    "match_expression": "option[93].hex == 0x0007",
    "next_server": "10.0.0.5",
    "boot_file_name": "ipxe.efi",
    "is_ipxe_chain": False,
}


def _scope(cidr: str, **over: object) -> dict[str, Any]:
    scope: dict[str, Any] = {
        "subnet_cidr": cidr,
        "address_family": "ipv4",
        "is_active": True,
        "lease_time": 3600,
        "options": {},
        "pools": [],
        "statics": [],
    }
    scope.update(over)
    return scope


def _render(*scopes: dict[str, Any], pxe: list[dict[str, Any]]) -> dict[str, Any]:
    return render(
        {
            "server": {"dhcp_socket_type": "raw"},
            "global_options": {"lease_time": 3600},
            "scopes": list(scopes),
            "pxe_classes": pxe,
        }
    )["Dhcp4"]


def test_a_pxe_class_is_evaluated_only_for_the_scopes_that_list_it() -> None:
    doc = _render(
        _scope("10.0.20.0/24", pxe_class_names=["pxe-a"]),
        _scope("10.0.21.0/24", pxe_class_names=[]),
        pxe=[PXE],
    )

    (cls,) = doc["client-classes"]
    assert cls == {
        "name": "pxe-a",
        "next-server": "10.0.0.5",
        "boot-file-name": "ipxe.efi",
        "test": "option[93].hex == 0x0007",
        "only-in-additional-list": True,
    }
    subnets = {s["subnet"]: s for s in doc["subnet4"]}
    assert subnets["10.0.20.0/24"]["evaluate-additional-classes"] == ["pxe-a"]
    assert "evaluate-additional-classes" not in subnets["10.0.21.0/24"]


def test_a_scope_lists_its_classes_in_the_order_sent() -> None:
    """The control plane sends a profile's classes in its priority order,
    the order the global render declared them in."""
    fallback = {**PXE, "name": "pxe-b", "match_expression": "", "boot_file_name": "any.efi"}
    doc = _render(_scope("10.0.20.0/24", pxe_class_names=["pxe-a", "pxe-b"]), pxe=[PXE, fallback])

    assert doc["subnet4"][0]["evaluate-additional-classes"] == ["pxe-a", "pxe-b"]


def test_a_match_with_no_test_is_scoped_too() -> None:
    """An empty match still means every client, now of its own scopes only."""
    doc = _render(
        _scope("10.0.20.0/24", pxe_class_names=["pxe-a"]),
        _scope("10.0.21.0/24", pxe_class_names=[]),
        pxe=[{**PXE, "match_expression": ""}],
    )

    (cls,) = doc["client-classes"]
    assert "test" not in cls
    assert cls["only-in-additional-list"] is True
    assert "evaluate-additional-classes" not in doc["subnet4"][1]


def test_a_control_plane_older_than_2731_keeps_the_classes_global() -> None:
    """A bundle whose scopes carry no ``pxe_class_names`` renders as before."""
    doc = _render(_scope("10.0.20.0/24"), pxe=[PXE])

    (cls,) = doc["client-classes"]
    assert "only-in-additional-list" not in cls
    assert "evaluate-additional-classes" not in doc["subnet4"][0]
