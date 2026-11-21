"""Vendor presets for DHCP option 43 (issue #4490).

Wireless controllers and some other gear find their controller through the
DHCP vendor-specific information option (43), and each vendor frames the
payload differently. A preset turns a controller address into the exact bytes
that vendor's devices expect, so nobody hex-encodes it by hand into a raw
``code:43`` row.

The result is the plain-hex string the option library already stores for a
binary option 43 (no ``0x``, no separators), so it flows through the phone
profile option set, ``validate_phone_options`` and the Kea ``binary`` option
definition unchanged.

**Only encodings confirmed against the vendor's own published documentation
are shipped.** Each preset carries its ``source``. Vendors whose framing could
not be confirmed from a primary source are deliberately absent (Aruba, whose
option 43 documentation could not be read; Meraki; Extreme / Aerohive; and
others) rather than guessed: a wrong option 43 silently fails to adopt a
device. The catalogue is static data in the repository; nothing here makes
an outbound call.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class VendorPreset:
    id: str
    vendor: str
    product: str
    description: str
    # How many controller addresses the framing carries.
    min_controllers: int
    max_controllers: int
    # What the operator is asked for, as a label for the form.
    controller_label: str
    # Option-60 prefix that fences the option to this vendor's devices, or
    # None where the vendor documents none as required.
    vendor_class_match: str | None
    vendor_class_note: str
    # Where the byte layout was confirmed.
    source: str
    encode: Callable[[list[ipaddress.IPv4Address]], bytes]
    option_code: int = 43


def _ipv4(text: str) -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address(text.strip())
    except ValueError as exc:
        raise ValueError(f"{text.strip()!r} is not an IPv4 address") from exc


# UniFi: sub-option 0x01, length 0x04, then the controller's four address
# bytes. Ubiquiti, "UniFi - Layer 3 methods for adoption" (help.ui.com
# article 204909754): worked example 172.16.30.3 -> 01:04:AC:10:1E:03.
def _encode_unifi(ips: list[ipaddress.IPv4Address]) -> bytes:
    return b"\x01\x04" + ips[0].packed


# Cisco lightweight APs: type 0xf1, length = 4 x controller count, then each
# WLC management address in order. Cisco, "DHCP Option 43 for Lightweight
# Cisco Aironet Access Points Configuration Example" (document 97066):
# 192.168.10.5 + 192.168.10.20 -> f108c0a80a05c0a80a14.
def _encode_cisco_wlc(ips: list[ipaddress.IPv4Address]) -> bytes:
    body = b"".join(ip.packed for ip in ips)
    return b"\xf1" + bytes([len(body)]) + body


# Ruckus: sub-option byte, then the length in bytes of the address STRING
# (dots included), then that string as ASCII. Ruckus support article
# 000008703 "Understanding DHCP Option 43 Hexadecimal code in Ruckus":
# 192.168.1.120 -> 060d3139322e3136382e312e313230, with 06 for SmartZone
# (SCG / vSZ) and 03 for ZoneDirector. The article documents one address
# only, so no multi-controller form is offered.
def _ruckus(sub_option: int) -> Callable[[list[ipaddress.IPv4Address]], bytes]:
    def enc(ips: list[ipaddress.IPv4Address]) -> bytes:
        text = str(ips[0]).encode("ascii")
        return bytes([sub_option, len(text)]) + text

    return enc


_RUCKUS_SOURCE = (
    "Ruckus support article 000008703, 'Understanding DHCP Option 43 " "Hexadecimal code in Ruckus'"
)

PRESETS: tuple[VendorPreset, ...] = (
    VendorPreset(
        id="cisco-wlc",
        vendor="Cisco",
        product="Lightweight APs (AireOS / Catalyst WLC)",
        description="WLC management addresses for Cisco lightweight access points.",
        min_controllers=1,
        max_controllers=63,
        controller_label="WLC management IPv4 address",
        vendor_class_match=None,
        vendor_class_note=(
            "Cisco does not require an option 60 match; add one (for example "
            "'Cisco AP c9120') only to hand different controllers to different AP models."
        ),
        source=(
            "Cisco document 97066, 'DHCP Option 43 for Lightweight Cisco Aironet "
            "Access Points Configuration Example'"
        ),
        encode=_encode_cisco_wlc,
    ),
    VendorPreset(
        id="unifi",
        vendor="Ubiquiti",
        product="UniFi Network",
        description="Controller address for UniFi devices adopting across subnets.",
        min_controllers=1,
        max_controllers=1,
        controller_label="UniFi controller IPv4 address",
        vendor_class_match="ubnt",
        vendor_class_note="Ubiquiti's article fences the option on option 60 'ubnt'.",
        source="Ubiquiti, 'UniFi - Layer 3 methods for adoption' (help.ui.com article 204909754)",
        encode=_encode_unifi,
    ),
    VendorPreset(
        id="ruckus-smartzone",
        vendor="Ruckus",
        product="SmartZone / vSZ (SCG)",
        description="SmartZone controller address for Ruckus access points (sub-option 06).",
        min_controllers=1,
        max_controllers=1,
        controller_label="SmartZone IPv4 address",
        vendor_class_match=None,
        vendor_class_note="Ruckus documents no option 60 string for this option.",
        source=_RUCKUS_SOURCE,
        encode=_ruckus(0x06),
    ),
    VendorPreset(
        id="ruckus-zonedirector",
        vendor="Ruckus",
        product="ZoneDirector",
        description="ZoneDirector address for Ruckus access points (sub-option 03).",
        min_controllers=1,
        max_controllers=1,
        controller_label="ZoneDirector IPv4 address",
        vendor_class_match=None,
        vendor_class_note="Ruckus documents no option 60 string for this option.",
        source=_RUCKUS_SOURCE,
        encode=_ruckus(0x03),
    ),
)


def list_presets() -> list[VendorPreset]:
    return sorted(PRESETS, key=lambda p: (p.vendor.lower(), p.product.lower()))


def get_preset(preset_id: str) -> VendorPreset | None:
    needle = preset_id.strip().lower()
    for p in PRESETS:
        if p.id == needle:
            return p
    return None


@dataclass(frozen=True)
class EncodedPreset:
    preset: VendorPreset
    value_hex: str
    byte_length: int


def encode_preset(preset: VendorPreset, controllers: list[str]) -> EncodedPreset:
    """Encode ``controllers`` for ``preset``. Raises ``ValueError`` with a
    message fit to show an operator."""
    ips = [_ipv4(c) for c in controllers if c.strip()]
    if len(ips) < preset.min_controllers:
        raise ValueError(f"{preset.product} needs at least {preset.min_controllers} address")
    if len(ips) > preset.max_controllers:
        raise ValueError(
            f"{preset.product} takes at most {preset.max_controllers} "
            f"address{'es' if preset.max_controllers != 1 else ''}"
        )
    raw = preset.encode(ips)
    return EncodedPreset(preset=preset, value_hex=raw.hex(), byte_length=len(raw))


__all__ = [
    "EncodedPreset",
    "PRESETS",
    "VendorPreset",
    "encode_preset",
    "get_preset",
    "list_presets",
]
