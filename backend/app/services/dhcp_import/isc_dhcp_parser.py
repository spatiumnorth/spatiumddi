"""ISC dhcpd.conf importer (issue #129 Phase 3).

The hardest source — ISC's ``dhcpd.conf`` is a brace-delimited,
semicolon-terminated declaration language with no robust open-source
Python parser, so we own a small tokeniser + recursive-descent walker
here. We parse the subset that maps to SpatiumDDI's model — ``subnet`` /
``subnet6`` blocks, ``range`` / ``range6`` / ``pool`` declarations,
``host`` reservations, scope ``option`` statements, and ``class``
declarations — and surface everything else (``failover``, ``key``,
``zone``, ``omapi``, classifier DSL we can't translate) in the
"didn't import" panel.

Pipeline:

1. Operator uploads ``dhcpd.conf`` (optionally with ``include`` files
   already inlined — we don't fetch ``include`` targets, we warn).
2. Tokenise (comment-aware, string-aware) → recursive-descent into a
   statement tree.
3. Walk the tree: ``subnet`` → :class:`ImportedScope`, ``range`` →
   :class:`ImportedPool`, ``host`` → :class:`ImportedReservation`,
   ``class`` → :class:`ImportedClientClass` (always flagged
   ``supported=False`` — ISC's runtime-expression DSL doesn't translate
   to our constrained class model, so classes are surfaced for manual
   review, never auto-created).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from app.services.dhcp.class_refs import reserved_name_reason

from .canonical import (
    ImportedClientClass,
    ImportedPool,
    ImportedReservation,
    ImportedScope,
    ImportPreview,
    pool_problem,
)
from .options import coerce_option_value, isc_option_to_canonical, normalise_mac

MAX_CONFIG_BYTES = 25 * 1024 * 1024

# Top-level / block keywords we recognise as "present but not imported".
_UNSUPPORTED_KEYWORDS: dict[str, str] = {
    "failover": "ISC failover peer config is not imported — set HA up at the SpatiumDDI "
    "server-group level post-import.",
    "key": "ISC TSIG key declarations are not imported — re-add DDNS keys server-side.",
    "zone": "ISC DDNS zone declarations are not imported — DDNS is configured per-subnet in "
    "SpatiumDDI.",
    "include": "ISC 'include' files are not fetched — inline them before upload or import each "
    "file separately.",
    "omapi-port": "ISC OMAPI config is not imported.",
    "omapi-key": "ISC OMAPI config is not imported.",
}


class IscImportError(ValueError):
    """Raised when the upload can't be tokenised / parsed at all."""


# ── tokeniser ────────────────────────────────────────────────────────


@dataclass
class _Tok:
    kind: str  # word | str | lbrace | rbrace | semi | comma
    value: str = ""


def _tokenize(text: str) -> list[_Tok]:
    toks: list[_Tok] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in " \t\r\n":
            i += 1
            continue
        if c == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        if c == '"':
            i += 1
            buf: list[str] = []
            while i < n and text[i] != '"':
                if text[i] == "\\" and i + 1 < n:
                    buf.append(text[i + 1])
                    i += 2
                    continue
                buf.append(text[i])
                i += 1
            i += 1  # closing quote
            toks.append(_Tok("str", "".join(buf)))
            continue
        if c == "{":
            toks.append(_Tok("lbrace"))
            i += 1
            continue
        if c == "}":
            toks.append(_Tok("rbrace"))
            i += 1
            continue
        if c == ";":
            toks.append(_Tok("semi"))
            i += 1
            continue
        if c == ",":
            toks.append(_Tok("comma"))
            i += 1
            continue
        # bare word — run until whitespace or a structural char
        start = i
        while i < n and text[i] not in ' \t\r\n{};,"#':
            i += 1
        toks.append(_Tok("word", text[start:i]))
    return toks


# ── statement tree ───────────────────────────────────────────────────


@dataclass
class _Stmt:
    parts: list[_Tok]  # the head tokens (before { or ;)
    children: list[_Stmt] | None = field(default=None)

    @property
    def keyword(self) -> str:
        return self.parts[0].value.lower() if self.parts and self.parts[0].kind == "word" else ""


def _parse_block(toks: list[_Tok], i: int) -> tuple[list[_Stmt], int]:
    stmts: list[_Stmt] = []
    cur: list[_Tok] = []
    n = len(toks)
    while i < n:
        t = toks[i]
        if t.kind == "semi":
            if cur:
                stmts.append(_Stmt(parts=cur))
                cur = []
            i += 1
        elif t.kind == "lbrace":
            children, i = _parse_block(toks, i + 1)
            stmts.append(_Stmt(parts=cur, children=children))
            cur = []
        elif t.kind == "rbrace":
            if cur:
                stmts.append(_Stmt(parts=cur))
            return stmts, i + 1
        else:
            cur.append(t)
            i += 1
    if cur:
        stmts.append(_Stmt(parts=cur))
    return stmts, i


# ── value helpers ────────────────────────────────────────────────────


def _value_tokens(parts: list[_Tok], start: int) -> Any:
    """Collect the value of an ``option name <value>`` style statement
    from token index ``start`` to the end, splitting on commas into a
    list. Single value collapses to a scalar."""
    groups: list[str] = []
    cur: list[str] = []
    for t in parts[start:]:
        if t.kind == "comma":
            if cur:
                groups.append(" ".join(cur))
                cur = []
            continue
        cur.append(t.value)
    if cur:
        groups.append(" ".join(cur))
    if not groups:
        return ""
    return coerce_option_value(groups)


# ── scope / reservation / class walkers ──────────────────────────────


def _parse_options_and_leases(
    body: list[_Stmt],
) -> tuple[dict[str, Any], int | None, int | None, int | None, list[str]]:
    """Extract option-data + lease-time params + parse warnings common
    to subnet / group / shared-network bodies."""
    options: dict[str, Any] = {}
    lease_time: int | None = None
    min_lt: int | None = None
    max_lt: int | None = None
    warnings: list[str] = []
    for st in body:
        kw = st.keyword
        if kw == "option" and len(st.parts) >= 2:
            name = isc_option_to_canonical(st.parts[1].value)
            options[name] = _value_tokens(st.parts, 2)
        elif kw == "default-lease-time" and len(st.parts) >= 2:
            lease_time = _safe_int(st.parts[1].value, lease_time)
        elif kw == "max-lease-time" and len(st.parts) >= 2:
            max_lt = _safe_int(st.parts[1].value, max_lt)
        elif kw == "min-lease-time" and len(st.parts) >= 2:
            min_lt = _safe_int(st.parts[1].value, min_lt)
        elif kw == "next-server":
            warnings.append(
                "'next-server' (PXE boot server) not auto-imported — wire it via a PXE profile "
                "(issue #51) post-import."
            )
        elif kw == "filename" and len(st.parts) >= 2:
            options["bootfile-name"] = _value_tokens(st.parts, 1)
    return options, lease_time, min_lt, max_lt, warnings


def _safe_int(value: str, fallback: int | None) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _parse_ranges(body: list[_Stmt]) -> tuple[list[ImportedPool], list[str]]:
    """Pull ``range`` / ``range6`` statements + ``pool {}`` blocks out of
    a subnet body."""
    pools: list[ImportedPool] = []
    warnings: list[str] = []
    for st in body:
        kw = st.keyword
        if kw in ("range", "range6"):
            pool = _range_to_pool(st)
            if pool is not None:
                pools.append(pool)
        elif kw == "pool" and st.children is not None:
            class_restriction = None
            for sub in st.children:
                if sub.keyword == "allow" and "members" in [p.value for p in sub.parts]:
                    # allow members of "class-name";
                    str_toks = [p.value for p in sub.parts if p.kind == "str"]
                    if str_toks:
                        class_restriction = str_toks[0]
                elif sub.keyword == "deny":
                    warnings.append(
                        "ISC pool-level 'deny' rule not imported — SpatiumDDI imports allowed "
                        "pools only."
                    )
            for sub in st.children:
                if sub.keyword in ("range", "range6"):
                    pool = _range_to_pool(sub, class_restriction=class_restriction)
                    if pool is not None:
                        pools.append(pool)
    return pools, warnings


def _range_to_pool(st: _Stmt, *, class_restriction: str | None = None) -> ImportedPool | None:
    # range [dynamic-bootp|dynamic|static] <start> [<end>];
    ips = [
        p.value
        for p in st.parts[1:]
        if p.kind == "word" and p.value.lower() not in ("dynamic-bootp", "dynamic", "static")
    ]
    if not ips:
        return None
    start_ip = ips[0]
    end_ip = ips[1] if len(ips) > 1 else ips[0]
    return ImportedPool(
        start_ip=start_ip, end_ip=end_ip, pool_type="dynamic", class_restriction=class_restriction
    )


def _parse_host(st: _Stmt) -> tuple[ImportedReservation | None, str | None]:
    """A ``host name { hardware ethernet MAC; fixed-address IP; }`` block.

    Returns (reservation, fixed_ip) — fixed_ip is used to attach a
    *global* host to the subnet whose CIDR contains it.
    """
    if st.children is None:
        return None, None
    mac: str | None = None
    ip: str | None = None
    hostname = ""
    if len(st.parts) >= 2:
        hostname = st.parts[1].value
    options: dict[str, Any] = {}
    for sub in st.children:
        kw = sub.keyword
        if kw == "hardware" and len(sub.parts) >= 3:
            mac = normalise_mac(sub.parts[2].value)
        elif kw in ("fixed-address", "fixed-address6") and len(sub.parts) >= 2:
            ip = sub.parts[1].value
        elif kw == "option" and len(sub.parts) >= 2:
            options[isc_option_to_canonical(sub.parts[1].value)] = _value_tokens(sub.parts, 2)
    if mac is None or not ip:
        return None, None
    return (
        ImportedReservation(ip_address=ip, mac_address=mac, hostname=hostname, options=options),
        ip,
    )


def _subnet_cidr(st: _Stmt) -> str | None:
    """Resolve the CIDR for a ``subnet <ip> netmask <mask>`` or
    ``subnet6 <cidr>`` declaration."""
    kw = st.keyword
    words = [p.value for p in st.parts if p.kind == "word"]
    try:
        if kw == "subnet6" and len(words) >= 2:
            return str(ipaddress.ip_network(words[1], strict=False))
        if kw == "subnet" and len(words) >= 4 and words[2].lower() == "netmask":
            return str(ipaddress.ip_network(f"{words[1]}/{words[3]}", strict=False))
    except ValueError:
        return None
    return None


def _build_scope(
    st: _Stmt,
    *,
    inherited_options: dict[str, Any],
    inherited_lease: int | None,
) -> tuple[ImportedScope | None, list[ImportedReservation]]:
    cidr = _subnet_cidr(st)
    if cidr is None:
        return None, []
    body = st.children or []
    options, lease_time, min_lt, max_lt, opt_warnings = _parse_options_and_leases(body)
    pools, range_warnings = _parse_ranges(body)
    kept: list[ImportedPool] = []
    for pool in pools:
        problem = pool_problem(pool.start_ip, pool.end_ip, cidr)
        if problem is None:
            kept.append(pool)
        else:
            range_warnings.append(f"Range {pool.start_ip} {pool.end_ip} not imported: {problem}.")
    pools = kept

    # host reservations declared directly inside the subnet block
    inline_res: list[ImportedReservation] = []
    for sub in body:
        if sub.keyword == "host":
            res, _ = _parse_host(sub)
            if res is not None:
                inline_res.append(res)

    af = "ipv6" if st.keyword == "subnet6" else "ipv4"
    merged_options = {**inherited_options, **options}
    return (
        ImportedScope(
            subnet_cidr=cidr,
            address_family=af,
            lease_time=lease_time or inherited_lease or 86400,
            min_lease_time=min_lt,
            max_lease_time=max_lt,
            options=merged_options,
            pools=pools,
            reservations=inline_res,
            parse_warnings=sorted(set(opt_warnings + range_warnings)),
        ),
        [],
    )


def _build_class(st: _Stmt) -> ImportedClientClass:
    name = ""
    str_toks = [p.value for p in st.parts if p.kind == "str"]
    if str_toks:
        name = str_toks[0]
    elif len(st.parts) >= 2:
        name = st.parts[1].value
    match_expr = ""
    for sub in st.children or []:
        if sub.keyword in ("match", "spawn"):
            match_expr = " ".join(p.value for p in sub.parts)
            break
    name = name or "unnamed-class"
    reserved = reserved_name_reason(name)
    return ImportedClientClass(
        name=name,
        match_expression=match_expr,
        description="Imported from ISC dhcpd.conf — review the match expression before enabling.",
        supported=False,
        warning=(
            f"Not imported: {reserved}."
            if reserved
            else "ISC classifier DSL doesn't map to SpatiumDDI's client-class model; "
            "left for manual review."
        ),
    )


# ── top-level walk ───────────────────────────────────────────────────


def parse_isc_config(data: bytes) -> ImportPreview:
    if len(data) > MAX_CONFIG_BYTES:
        raise IscImportError(f"Upload exceeds {MAX_CONFIG_BYTES // (1024 * 1024)} MB limit")
    if not data:
        raise IscImportError("Empty upload")
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        raise IscImportError(f"Could not read upload as text: {exc}") from exc

    toks = _tokenize(text)
    stmts, _ = _parse_block(toks, 0)

    scopes: list[ImportedScope] = []
    client_classes: list[ImportedClientClass] = []
    global_hosts: list[ImportedReservation] = []
    warnings: list[str] = []
    unsupported: list[str] = []

    # Global defaults (top-level options + lease times) become the base
    # every subnet inherits.
    g_options, g_lease, _, _, g_warn = _parse_options_and_leases(stmts)
    warnings.extend(g_warn)

    def _walk(container: list[_Stmt], depth_label: str | None) -> None:
        for st in container:
            kw = st.keyword
            if kw in ("subnet", "subnet6"):
                scope, _ = _build_scope(st, inherited_options=g_options, inherited_lease=g_lease)
                if scope is not None:
                    scopes.append(scope)
                else:
                    warnings.append("Skipped a subnet declaration with an unparseable CIDR.")
            elif kw == "shared-network" and st.children is not None:
                warnings.append(
                    "'shared-network' grouping flattened — member subnets imported individually."
                )
                _walk(st.children, "shared-network")
            elif kw == "group" and st.children is not None:
                _walk(st.children, "group")
            elif kw == "host":
                res, ip = _parse_host(st)
                if res is not None:
                    global_hosts.append(res)
            elif kw == "class" and st.children is not None:
                client_classes.append(_build_class(st))
            elif kw == "subclass":
                unsupported.append(
                    "ISC 'subclass' membership rules are not imported (manual review)."
                )
            elif kw in _UNSUPPORTED_KEYWORDS:
                unsupported.append(_UNSUPPORTED_KEYWORDS[kw])

    _walk(stmts, None)

    # Attach global host reservations to the subnet whose CIDR contains
    # the fixed-address.
    nets: list[tuple[Any, ImportedScope]] = []
    for s in scopes:
        try:
            nets.append((ipaddress.ip_network(s.subnet_cidr, strict=False), s))
        except ValueError:
            continue
    unattached = 0
    for host in global_hosts:
        try:
            addr = ipaddress.ip_address(host.ip_address)
        except ValueError:
            unattached += 1
            continue
        placed = False
        for net, scope in nets:
            if addr in net:
                scope.reservations.append(host)
                placed = True
                break
        if not placed:
            unattached += 1
    if unattached:
        warnings.append(
            f"{unattached} global host reservation(s) couldn't be matched to an imported subnet "
            "(no containing subnet, or a non-IP fixed-address) — skipped."
        )

    if not scopes and not client_classes:
        raise IscImportError("No subnet declarations found — is this an ISC dhcpd.conf?")

    af_hist: dict[str, int] = {}
    for s in scopes:
        af_hist[s.address_family] = af_hist.get(s.address_family, 0) + 1

    return ImportPreview(
        source="isc_dhcp",
        scopes=scopes,
        client_classes=client_classes,
        conflicts=[],
        warnings=sorted(set(warnings)),
        unsupported=sorted(set(unsupported)),
        total_pools=sum(len(s.pools) for s in scopes),
        total_reservations=sum(len(s.reservations) for s in scopes),
        address_family_histogram=af_hist,
    )
