"""DHCP option names and values, checked on write (#1228).

Scope, pool, static, option-template, client-class and device-policy options
are free-form ``{name: value}`` mappings, and until #1228 only the two FQDN
options were checked. That mattered more than it looks, because of how the
two failure modes land:

* a **value** Kea cannot parse — ``routers: "10.0.0.1, bogus"``, an MTU of
  70000, a raw ``code:43`` holding text where hex is required — makes Kea
  reject the ENTIRE config for the server group. Since #882 the agent reverts
  and alerts, but every later change to the group is blocked behind it until
  somebody finds the bad option. The builtin DHCP Editor role can write one;
* a **name** the renderer does not know is dropped by the agent with a log
  line nobody reads. The operator sees the option saved and it is never
  served.

So the vocabulary here is the RENDERER's, not the IANA catalogue's: a name is
accepted only if ``render_kea`` will actually emit it. The tables are imported
from the Kea driver rather than copied, which is the #856 lesson — a second
copy of an option table drifts.

Accepted keys:

* the canonical SpatiumDDI names (``STANDARD_OPTION_NAMES`` for DHCPv4, the
  Kea v6 name map for DHCPv6), each with a value type;
* ``code:NN`` for the raw codes SpatiumDDI ships an ``option-def`` for — the
  agent strips any other raw code, and Kea types an undefined one as binary,
  so no other code can be delivered;
* ``opt-NN``, the Windows DHCP importer's spelling for an option it does not
  canonicalise. Only the Windows driver reads it, and the Windows cmdlet
  checks the value, so only the code range is checked here.

Which raw spelling a group accepts depends on its servers (#1296), because
each driver silently drops the other's: Kea and FortiGate read ``code:NN``
and skip ``opt-NN``, Windows reads ``opt-NN`` and skips ``code:NN``. So the
caller passes ``raw_codes``: ``"code"`` for a group with no Windows member
(Kea, FortiGate, or no servers yet), ``"opt"`` for an all-Windows group, and
``"none"`` for a group mixing Windows with another driver, where neither
spelling reaches every member. (#1110 refuses only the Kea + Windows mix for
new servers; FortiGate + Windows can still be assembled.)

Everything else — including ``option_data``, the raw Kea passthrough that
internal producers (#972) merge in at bundle time — is refused.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Mapping
from functools import lru_cache
from typing import Any

from app.core.dns_names import contains_control_chars, validate_fqdn
from app.drivers.dhcp.base import STANDARD_OPTION_NAMES
from app.drivers.dhcp.kea import (
    _KEA_OPTION_NAMES,
    _KEA_OPTION_NAMES_V6,
    _KEA_VENDOR_OPTION_DEFS,
)
from app.services.dhcp.option_codes import get_by_code
from app.services.dhcp.voip_options import load_catalog as load_voip_catalog

# Canonical code → SpatiumDDI name, for list-form entries that carry a code.
CODE_TO_NAME: dict[int, str] = {
    2: "time-offset",
    3: "routers",
    6: "dns-servers",
    15: "domain-name",
    26: "mtu",
    28: "broadcast-address",
    42: "ntp-servers",
    66: "tftp-server-name",
    67: "bootfile-name",
    119: "domain-search",
    150: "tftp-server-address",
}

# Other spellings that collapse onto a canonical name. ``domain-name-servers``
# is what the frontend historically sent for option 6 (#583); the Kea
# spellings are accepted because the agent already reads them (#856) and an
# API client that speaks Kea should not be refused for it.
OPTION_NAME_ALIASES: dict[str, str] = {
    "domain-name-servers": "dns-servers",
    "interface-mtu": "mtu",
    "boot-file-name": "bootfile-name",
}

_RAW_CODE = re.compile(r"^code:(\d+)$")
_WINDOWS_CODE = re.compile(r"^opt-(\d+)$")
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_NAME_TO_CODE: dict[str, int] = {v: k for k, v in CODE_TO_NAME.items()}


def option_key_code(key: str) -> int | None:
    """The DHCP option code a stored key stands for, or ``None``.

    Covers the canonical names, their aliases, and the ``code:NN`` /
    ``opt-NN`` raw spellings, so a raw code reads back under its own number
    rather than as ``0``.
    """
    canon = OPTION_NAME_ALIASES.get(key, key)
    if canon in _NAME_TO_CODE:
        return _NAME_TO_CODE[canon]
    m = _RAW_CODE.fullmatch(key) or _WINDOWS_CODE.fullmatch(key)
    return int(m.group(1)) if m else None


def _is_unset(value: Any) -> bool:
    """The renderer skips these for a named option, so they are not an error."""
    return value is None or value == "" or value == []


def _items(value: Any) -> list[Any]:
    """A list option arrives as a list, or as the comma-separated string the
    renderer would have joined it into."""
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [p for p in (s.strip() for s in value.split(",")) if p]
    return [value]


def _scalar(value: Any) -> Any:
    """A single-valued option; a one-element list is accepted because the
    Windows importer wraps every value in one."""
    if isinstance(value, list):
        if len(value) != 1:
            raise ValueError("takes a single value, not a list")
        return value[0]
    return value


def _check_ip_list(value: Any, version: int) -> None:
    items = _items(value)
    if not items:
        raise ValueError(f"needs at least one IPv{version} address")
    for item in items:
        if not isinstance(item, str):
            raise ValueError(f"{item!r} is not an IPv{version} address")
        try:
            addr = ipaddress.ip_address(item.strip())
        except ValueError:
            raise ValueError(f"{item!r} is not an IPv{version} address") from None
        if addr.version != version:
            raise ValueError(f"{item!r} is not an IPv{version} address")


def _ipv4_list(value: Any) -> None:
    _check_ip_list(value, 4)


def _ipv6_list(value: Any) -> None:
    _check_ip_list(value, 6)


def _ipv4(value: Any) -> None:
    _check_ip_list([_scalar(value)], 4)


def _string(value: Any) -> None:
    v = _scalar(value)
    if isinstance(v, bool) or not isinstance(v, (str, int)):
        raise ValueError("must be a string")
    text = str(v)
    if not text.strip():
        raise ValueError("must not be blank")
    if contains_control_chars(text):
        raise ValueError("must not contain control characters")


def _integer(low: int, high: int) -> Callable[[Any], None]:
    def check(value: Any) -> None:
        v = _scalar(value)
        if isinstance(v, bool):
            raise ValueError("must be an integer")
        try:
            n = int(str(v).strip())
        except ValueError:
            raise ValueError(f"{v!r} is not an integer") from None
        if not low <= n <= high:
            raise ValueError(f"{n} is outside {low}..{high}")

    return check


def _fqdn(value: Any) -> None:
    v = _scalar(value)
    if not isinstance(v, str) or not v.strip():
        raise ValueError("must not be blank")
    validate_fqdn(v, field="value")


def _fqdn_list(value: Any) -> None:
    items = _items(value)
    if not items:
        raise ValueError("needs at least one domain")
    for item in items:
        if not isinstance(item, str) or not item.strip():
            raise ValueError("contains a blank entry")
        validate_fqdn(item, field="value")


def _hex(value: Any) -> None:
    v = _scalar(value)
    if not isinstance(v, str) or not v:
        raise ValueError("must be hex digits")
    # Measured against kea-dhcp4 3.0.3 with a ``binary`` option-def: a ``0x``
    # prefix, ``:`` separators and an odd digit count are all rejected, and
    # take the whole config with them.
    if not _HEX.fullmatch(v):
        raise ValueError("must be hex digits only, with no 0x prefix and no separators")
    if len(v) % 2:
        raise ValueError("must be an even number of hex digits (whole bytes)")


_V4_CHECKS: dict[str, Callable[[Any], None]] = {
    "routers": _ipv4_list,
    "dns-servers": _ipv4_list,
    "ntp-servers": _ipv4_list,
    "tftp-server-address": _ipv4_list,
    "broadcast-address": _ipv4,
    "domain-name": _fqdn,
    "domain-search": _fqdn_list,
    "tftp-server-name": _string,
    "bootfile-name": _string,
    # RFC 2132 §5.1: the minimum legal MTU is 68.
    "mtu": _integer(68, 65535),
    "time-offset": _integer(-(2**31), 2**31 - 1),
}

_V6_CHECKS: dict[str, Callable[[Any], None]] = {
    "dns-servers": _ipv6_list,
    "ntp-servers": _ipv6_list,
    "domain-search": _fqdn_list,
    "bootfile-name": _string,  # rendered as bootfile-url
}


def renderer_vocabularies() -> tuple[set[str], set[str], set[str], set[str], set[str]]:
    """The checked names beside the renderer's own tables, for the test that
    pins them equal — adding an option to the Kea driver without a value check
    here then fails CI instead of being refused as unknown."""
    return (
        set(_V4_CHECKS),
        set(STANDARD_OPTION_NAMES),
        set(_KEA_OPTION_NAMES),
        set(_V6_CHECKS),
        set(_KEA_OPTION_NAMES_V6),
    )


def _raw_code_check(code: int) -> Callable[[Any], None]:
    spec = _KEA_VENDOR_OPTION_DEFS[code]
    kind = spec.get("type")
    if kind == "binary":
        return _hex
    if kind == "ipv4-address":
        return _ipv4_list if spec.get("array") else _ipv4
    return _string


def _describe_code(code: int) -> str:
    known = get_by_code(code)
    return f"option {code} ({known.name})" if known else f"option {code}"


def normalize_options(raw: Any) -> dict[str, Any]:
    """Accept ``{name: value}`` or ``[{code, name, value}, …]``; return a mapping.

    Does not validate. A list entry is keyed by its name when that name is one
    SpatiumDDI renders, else by its code: the custom-options editor sends the
    IANA catalogue name (``vendor-encapsulated-options``), which the renderer
    does not know, alongside a code (43) it can deliver as ``code:43``.
    """
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return {OPTION_NAME_ALIASES.get(str(k), str(k)): v for k, v in raw.items()}
    if not isinstance(raw, list):
        return {}
    out: dict[str, Any] = {}
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        name = OPTION_NAME_ALIASES.get(str(name), str(name)) if name else None
        code = entry.get("code")
        try:
            code_int = int(code) if code not in (None, "", 0, "0") else None
        except (TypeError, ValueError):
            code_int = None
        known = name is not None and (
            name in _V4_CHECKS or name in _V6_CHECKS or _is_code_key(name)
        )
        # A raw-code name (``code:43``) that disagrees with the entry's code
        # yields to the code: the options editor updates ``code`` as the
        # operator retypes it and leaves the old name behind, so keying by the
        # name would silently discard the change. Canonical names are left
        # alone — their code differs by family (v6 ``dns-servers`` is 23).
        if (
            known
            and code_int is not None
            and _is_code_key(str(name))
            and option_key_code(str(name)) != code_int
        ):
            known = False
        if known:
            key = str(name)
        elif code_int is not None:
            key = CODE_TO_NAME.get(code_int) or f"code:{code_int}"
        elif name:
            key = name  # unknown, and validation will say so
        else:
            continue
        out[key] = entry.get("value")
    return out


def _is_code_key(key: str) -> bool:
    return bool(_RAW_CODE.fullmatch(key) or _WINDOWS_CODE.fullmatch(key))


def _supported(address_family: str) -> str:
    names = sorted(_V6_CHECKS if address_family == "ipv6" else _V4_CHECKS)
    return ", ".join(names)


RAW_CODES_KEA = "code"
RAW_CODES_WINDOWS = "opt"
RAW_CODES_NONE = "none"


def _refuse_raw_spelling(key: str, code: str, raw_codes: str) -> None:
    """Refuse a raw-code key the group's servers would drop (#1296)."""
    if raw_codes == RAW_CODES_NONE:
        raise ValueError(
            f"option '{key}': this group mixes Windows and non-Windows DHCP servers, and "
            "each drops the other's raw option spelling (Windows reads opt-NN, Kea and "
            "FortiGate read code:NN), so no raw code reaches every server; use a named "
            "option, or move the servers into single-driver groups"
        )
    if key.startswith("opt-") and raw_codes != RAW_CODES_WINDOWS:
        raise ValueError(
            f"option '{key}': opt-NN is the Windows DHCP spelling, and this group's "
            f"servers drop it; use code:{code}"
        )
    if key.startswith("code:") and raw_codes == RAW_CODES_WINDOWS:
        raise ValueError(f"option '{key}': Windows DHCP servers drop code:NN; use opt-{code}")


def _check_one(key: str, value: Any, address_family: str, raw_codes: str = RAW_CODES_KEA) -> None:
    """Raise ``ValueError`` naming ``key`` when it cannot be rendered."""
    if key == "option_data":
        raise ValueError(
            "option 'option_data' (raw Kea option-data) cannot be set over the API; "
            "use named options or code:NN"
        )

    raw = _RAW_CODE.fullmatch(key)
    if raw:
        code = int(raw.group(1))
        # Before the spelling check: naming the other spelling on a v6 scope
        # would send the operator to a key that is refused too.
        if address_family == "ipv6":
            raise ValueError(f"option '{key}': raw option codes are DHCPv4 only")
        _refuse_raw_spelling(key, raw.group(1), raw_codes)
        if code not in _KEA_VENDOR_OPTION_DEFS:
            supported = ", ".join(f"code:{c}" for c in sorted(_KEA_VENDOR_OPTION_DEFS))
            raise ValueError(
                f"option '{key}': SpatiumDDI cannot deliver {_describe_code(code)} "
                f"to Kea; raw codes it can deliver are {supported}"
            )
        if _is_unset(value):
            raise ValueError(f"option '{key}': has no value")
        try:
            _raw_code_check(code)(value)
        except ValueError as exc:
            raise ValueError(f"option '{key}': {exc}") from None
        return

    win = _WINDOWS_CODE.fullmatch(key)
    if win:
        if address_family == "ipv6" and raw_codes != RAW_CODES_WINDOWS:
            # The ``code:NN`` the spelling check would suggest is v4-only.
            raise ValueError(f"option '{key}': raw option codes are DHCPv4 only")
        _refuse_raw_spelling(key, win.group(1), raw_codes)
        if not 1 <= int(win.group(1)) <= 254:
            raise ValueError(f"option '{key}': option codes run 1..254")
        return

    # A client class ("any") renders into Dhcp4 unconditionally, and into
    # Dhcp6 only when the group has v6 scopes, so a key Dhcp4 knows must be
    # valid there: an IPv6 ``dns-servers`` would reach Dhcp4 as
    # ``domain-name-servers`` and take the whole config down. Dhcp4's table
    # is therefore consulted first for "any", and v6 only for a v6-only key.
    tables = {"ipv4": (_V4_CHECKS,), "ipv6": (_V6_CHECKS,)}.get(
        address_family, (_V4_CHECKS, _V6_CHECKS)
    )
    check = next((t[key] for t in tables if key in t), None)
    if check is None:
        if address_family == "ipv6" and key in _V4_CHECKS:
            raise ValueError(f"option '{key}': has no DHCPv6 equivalent")
        raise ValueError(
            f"unknown DHCP option '{key}'; supported names are "
            f"{_supported(address_family if address_family != 'any' else 'ipv4')}, "
            f"or code:NN for a raw code"
        )
    if _is_unset(value):
        return
    try:
        check(value)
    except ValueError as exc:
        raise ValueError(f"option '{key}': {exc}") from None


def validate_options(
    options: Mapping[str, Any],
    *,
    address_family: str = "ipv4",
    previous: Mapping[str, Any] | None = None,
    raw_codes: str = RAW_CODES_KEA,
) -> None:
    """Raise ``ValueError`` naming the first option that cannot be rendered.

    ``address_family`` is ``ipv4``, ``ipv6``, or ``any`` for a client class,
    which always renders into Dhcp4 and so is checked against Dhcp4 first.
    ``raw_codes`` is the raw-code spelling the group's servers read; see the
    module docstring.

    A key whose value is unchanged from ``previous`` is skipped, so an edit
    that round-trips a grandfathered option — stored before this check existed,
    or brought in by an importer — is not blocked by it (the #597 stance).
    """
    for key, value in _changed_options(options, previous):
        _check_one(key, value, address_family, raw_codes)


def _changed_options(
    options: Mapping[str, Any], previous: Mapping[str, Any] | None
) -> list[tuple[str, Any]]:
    """The ``(key, value)`` pairs of ``options`` not unchanged from ``previous``."""
    # Compare against the stored map under canonical names, so a row stored
    # under a legacy alias (``domain-name-servers``, #583) that the write
    # normalised still counts as unchanged.
    prev = {OPTION_NAME_ALIASES.get(str(k), str(k)): v for k, v in (previous or {}).items()}
    return [
        (str(key), value)
        for key, value in options.items()
        if not (str(key) in prev and prev[str(key)] == value)
    ]


def changes_raw_code(options: Mapping[str, Any], previous: Mapping[str, Any] | None = None) -> bool:
    """Whether ``options`` sets a raw-code key (``code:NN`` / ``opt-NN``) that
    ``validate_options`` would check — the only case ``raw_codes`` matters."""
    return any(_is_code_key(key) for key, _ in _changed_options(options, previous))


# ── Phone profiles (#1294) ──────────────────────────────────────────────────

# The value the VoIP starter pack seeds every option with, for the operator to
# replace. A profile is refused ``enabled`` while one is left.
PHONE_PLACEHOLDER = "CHANGE-ME"


def phone_option_key(code: int) -> str:
    """The key a phone-profile option is rendered under (#1294).

    A phone option names its CODE explicitly; the name beside it is a label.
    So the code decides what is delivered: the canonical name when SpatiumDDI
    has one for it (66 → ``tftp-server-name``), else ``code:NN``. Keying by the
    catalogue name (``polycom-config-url``) is what the agent dropped, so
    option 160 never reached a phone.
    """
    return CODE_TO_NAME.get(code) or f"code:{code}"


def _row_code(row: Mapping[str, Any]) -> int:
    """The row's option code, or 0 when it has none usable."""
    raw = row.get("code")
    try:
        return int(raw) if raw is not None else 0
    except (TypeError, ValueError):
        return 0


def _label_code(name: Any) -> int | None:
    """The option code a row's label names, or ``None`` when it names none.

    Covers the renderer's own vocabulary (canonical names, their aliases,
    ``code:NN``) and the VoIP catalogue's names (``polycom-config-url`` → 160).
    """
    if not name:
        return None
    code = option_key_code(str(name))
    if code is not None:
        return code
    return _voip_name_codes().get(str(name))


@lru_cache(maxsize=1)
def _voip_name_codes() -> dict[str, int]:
    return {o.name: o.code for v in load_voip_catalog() for o in v.options}


def _phone_row_key(row: Mapping[str, Any]) -> str | None:
    """The key one phone row renders under, or ``None`` when it renders nothing.

    The code decides. The one exception is a row stored before #1294 whose
    label contradicts its code: the write path refuses those now, but before
    it the LABEL decided when the agent knew it (``tftp-server-address`` or
    ``code:NN``) and the row was dropped when it did not (a catalogue name).
    Such a row keeps that behaviour, so an upgrade neither moves a working
    option to another code nor starts delivering one that never went out.
    """
    if not row.get("value"):
        return None
    code = _row_code(row)
    if not code:
        return None
    name = row.get("name")
    named = _label_code(name)
    if named is None or named == code:
        return phone_option_key(code)
    if option_key_code(str(name)) is None:
        return None  # a catalogue name the agent never knew: never delivered
    canon = OPTION_NAME_ALIASES.get(str(name), str(name))
    return canon if canon in _V4_CHECKS else f"code:{named}"


def phone_options_map(rows: Any) -> dict[str, Any]:
    """``[{code, name, value}, …]`` → the mapping a phone class renders.
    Rows with no value, or no usable code, are skipped."""
    out: dict[str, Any] = {}
    for row in rows or ():
        if not isinstance(row, dict):
            continue
        key = _phone_row_key(row)
        if key is not None:
            out[key] = row["value"]
    return out


def _row_identity(row: Any) -> tuple[int, str, str] | None:
    if not isinstance(row, dict):
        return None
    return (_row_code(row), str(row.get("name") or ""), str(row.get("value") or ""))


def validate_phone_options(
    rows: Any,
    *,
    previous: Any = None,
    going_live: bool = False,
    enabled: bool = False,
) -> None:
    """Raise ``ValueError`` naming the first phone option Kea could not load.

    Checks what ``phone_options_map`` will render, against DHCPv4 (a phone
    class is Dhcp4-only). Also refuses a code listed twice (one would silently
    win) and a label naming a different option than its code. Options
    unchanged from ``previous`` are skipped — the #597 stance, so a stored
    profile stays editable — unless the profile is going live, when every
    option is checked and a starter-pack placeholder left in is refused. A
    changed option on a profile that is (or stays) ``enabled`` is refused the
    placeholder too.
    """
    stored = (
        set()
        if going_live or previous is None
        else {i for i in map(_row_identity, previous or ()) if i is not None}
    )
    seen: dict[int, bool] = {}  # code → that row is unchanged from ``previous``
    for row in rows or ():
        if not isinstance(row, dict) or not row.get("value"):
            continue
        code = _row_code(row)
        if not code:
            raise ValueError(f"option code {row.get('code')!r} is not a DHCP option code")
        unchanged = _row_identity(row) in stored
        if code in seen and not (unchanged and seen[code]):
            raise ValueError(f"option {code} is listed twice")
        seen[code] = unchanged
        if unchanged:
            continue
        name = row.get("name")
        named = _label_code(name)
        if named is not None and named != code:
            raise ValueError(
                f"option {code} is labelled '{name}', which is option {named}; "
                "the code is what is delivered, so fix one or the other"
            )
        if (going_live or enabled) and str(row["value"]).strip() == PHONE_PLACEHOLDER:
            raise ValueError(
                f"option {code} still holds the starter pack's '{PHONE_PLACEHOLDER}' "
                "placeholder; set its real value before enabling the profile"
            )
    validate_options(
        phone_options_map(rows),
        address_family="ipv4",
        previous=None if going_live or previous is None else phone_options_map(previous),
    )


def phone_options_loadable(rows: Any) -> tuple[dict[str, Any], list[str]]:
    """What a phone class may render, and the keys dropped from it (#1294).

    Only options Kea can load: a profile stored before its options were
    checked may hold a value Kea rejects (the starter pack's CHANGE-ME in
    binary option 43), and one bad option rejects the WHOLE config.
    """
    kept: dict[str, Any] = {}
    dropped: list[str] = []
    for key, value in phone_options_map(rows).items():
        try:
            _check_one(key, value, "ipv4")
        except ValueError:
            dropped.append(key)
            continue
        kept[key] = value
    return kept, dropped


# ── option-60 vendor-class match (#1294, #1357) ──────────────────────────────


def vendor_class_match_renderable(value: str | None) -> bool:
    """True when *value* can sit inside Kea's ``=='<match>'`` string literal.

    A phone profile (#1294) and a PXE arch-match (#1357) both render their
    ``vendor_class_match`` as ``substring(option[60].hex,0,N)=='<match>'``.
    A ``'`` ends the literal early and Kea's lexer refuses a newline inside
    one; either rejects the WHOLE config (measured, kea-dhcp4 3.0.3).
    Control characters have no business in option 60 anyway.
    """
    return value is None or ("'" not in value and not contains_control_chars(value))


def check_vendor_class_match(value: str | None) -> str | None:
    """Pydantic validator body for ``vendor_class_match`` on write."""
    if not vendor_class_match_renderable(value):
        raise ValueError(
            f"vendor_class_match {value!r} may not contain ' or control characters — "
            "it is rendered inside a Kea string literal"
        )
    return value


def vendor_class_match_test(value: str) -> str:
    """The Kea ``test`` term matching an option-60 prefix.

    Measured in bytes, not characters: ``option[60].hex`` is the raw
    option, so a non-ASCII prefix measured in characters never matched.
    The caller must have checked :func:`vendor_class_match_renderable`.

    A non-ASCII prefix renders as a hex literal, not a quoted string. The
    agent writes Kea's config with ``json.dumps``' default ASCII escaping,
    and Kea's JSON lexer reads ``\\u00XX`` as ONE byte and refuses anything
    above ``\\u00ff`` outright (measured, kea-dhcp4 3.0.3): ``'Vendör'``
    would compare six bytes against a seven-byte prefix and never match,
    and ``'V€'`` would reject the group's whole config. ASCII keeps the
    quoted form so an existing bundle's ETag does not move.
    """
    raw = value.encode("utf-8")
    n = len(raw)
    if value.isascii():
        return f"substring(option[60].hex,0,{n})=='{value}'"
    return f"substring(option[60].hex,0,{n})==0x{raw.hex().upper()}"
