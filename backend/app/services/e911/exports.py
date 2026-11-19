"""E911 exports — CSV and IOS LLDP-MED snippets (#972 Phase 3).

Two generated artefacts, and **neither makes an outbound connection or
writes a device**. SpatiumDDI does not push switch configuration (see
[#60], closed as not planned); these produce text an operator reads,
reviews, and applies themselves.

* **CSV** — every ERL with its civic elements, ELINs, validation verdict and
  the network bindings pointing at it. For bulk review, for a spreadsheet an
  auditor asked for, and as the thing a shop already running Cisco Emergency
  Responder maps into CER's own ERL bulk load.
* **IOS snippets** — `location civic-location` / `location elin-location`
  stanzas plus the per-interface `location civic-location-id` lines, so a
  switch can announce location to phones over LLDP-MED. That is the one
  delivery mechanism that needs no HELD, no DHCP option and no phone-side
  configuration at all.

**The load-bearing work here is sanitisation, not formatting.** Both outputs
interpolate operator-typed free text, and both targets treat a newline as a
statement separator:

* A room named ``312\\nno logging`` in an IOS snippet is arbitrary
  configuration pasted into a switch by an operator who trusted us.
* A building named ``=cmd|' /C calc'!A0`` in a CSV is a formula that executes
  when the file is opened in Excel.

So every value is sanitised for its target, and a value that cannot be made
safe is dropped with a comment saying so rather than silently mangled — an
ERL missing its room is visibly incomplete, where a quietly-altered one is
not.

**Verification status, stated plainly:** the IOS command shape follows the
Cisco LLDP-MED location configuration guide and has **not** been applied to
a real switch from this code, which is why the snippet carries a header
saying it is generated for review. The CSV column names are ours; CER's
bulk-load columns differ between versions, so the operator maps them. Both
points are in the docs rather than implied away.

[#60]: https://github.com/spatiumnorth/spatiumddi/issues/60
"""

from __future__ import annotations

import csv
import io
import re
from datetime import UTC, datetime

from app.models.e911 import CIVIC_ELEMENTS, EmergencyResponseLocation, ERLBinding

#: Leading characters a spreadsheet treats as the start of a formula.
#: Prefixed with a single quote on export, which Excel and LibreOffice both
#: render as the literal text.
_FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")

#: Anything that is not safe inside an IOS command argument. Newlines and
#: carriage returns are the dangerous ones (a statement separator); the rest
#: are characters IOS parses specially and that no real address needs.
_IOS_FORBIDDEN = re.compile(r"[\r\n\x00-\x1f\x7f]")

#: IOS caps a civic-location sub-command argument well below this, but the
#: exact limit varies by platform; 250 is under every one we know of and is
#: far past any real address element.
_IOS_MAX_VALUE = 250

#: Civic element → IOS `location civic-location` sub-command keyword.
#:
#: Only the elements IOS has a keyword for. An element with no keyword is
#: reported in the snippet's summary rather than dropped in silence: the
#: operator needs to know that "seat 14" did not make it into the switch
#: config, because the phone will not announce it.
IOS_CIVIC_KEYWORDS: dict[str, str] = {
    "country": "country",
    "a1": "state",
    "a2": "county",
    "a3": "city",
    "a4": "division",
    "a5": "neighborhood",
    "rd": "street-group",
    "hno": "number",
    "sts": "street-suffix",
    "pod": "trailing-street-suffix",
    "prd": "leading-street-direction",
    "bld": "building",
    "flr": "floor",
    "unit": "unit",
    "room": "room",
    "loc": "additional-location-information",
    "nam": "name",
    "pc": "postal-code",
    "pobox": "post-office-box",
    "plc": "type-of-place",
    "lmk": "landmark",
}


def _is_number(text: str) -> bool:
    try:
        float(text)
    except ValueError:
        return False
    return True


def _csv_safe(value: object) -> str:
    """Stringify for CSV, defusing spreadsheet formula injection.

    A building named ``=cmd|' /C calc'!A0`` is a formula that executes when
    the file is opened. Prefixing a single quote is what every spreadsheet
    reads as "this is text".

    **A plain negative number is left alone**, which is why the check is not
    just ``startswith``. ``-`` is a formula leader, and every Southern or
    Western coordinate starts with one — quoting those would import latitude,
    longitude and altitude as TEXT in the spreadsheet this export exists for,
    so the columns could not be sorted, plotted or summed. A leading ``-``
    followed by something that is not a number is still quoted.
    """
    if value is None:
        return ""
    text = str(value)
    if text.startswith(_FORMULA_LEADERS) and not _is_number(text):
        return "'" + text
    return text


#: Public name for the other CSV exports (#4171 reuses it for the query log).
csv_safe = _csv_safe


def _ios_safe(value: object) -> str | None:
    """An IOS command argument, or None when the value cannot be made safe.

    None rather than a scrubbed string: a room whose name contained a newline
    is not a room whose name is the part before the newline, and silently
    shortening it would put a phone in the wrong place while looking fine.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if _IOS_FORBIDDEN.search(text):
        return None
    if len(text) > _IOS_MAX_VALUE:
        return None
    return text


CSV_COLUMNS: tuple[str, ...] = (
    "erl_name",
    "site_id",
    "elins",
    "validation_state",
    "validated_at",
    "validation_source",
    "is_dispatchable",
    "is_active",
    *(c for c, _n, _t, _d in CIVIC_ELEMENTS),
    "latitude",
    "longitude",
    "altitude",
    "altitude_unit",
    "binding_count",
    "binding_rules",
    "notes",
)


def render_csv(
    rows: list[tuple[EmergencyResponseLocation, list[ERLBinding]]],
) -> str:
    """One row per ERL, with its bindings summarised.

    ``\\r\\n`` line endings, because that is what RFC 4180 specifies and what
    every spreadsheet on Windows expects; Python's csv module does it when
    asked and mangles embedded newlines if it is not.
    """
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(CSV_COLUMNS), lineterminator="\r\n")
    writer.writeheader()
    for erl, bindings in rows:
        record: dict[str, str] = {
            "erl_name": _csv_safe(erl.name),
            "site_id": _csv_safe(erl.site_id),
            "elins": _csv_safe(" ".join(erl.elins or [])),
            "validation_state": _csv_safe(erl.validation_state),
            "validated_at": _csv_safe(
                erl.validated_at.strftime("%Y-%m-%dT%H:%M:%SZ") if erl.validated_at else ""
            ),
            "validation_source": _csv_safe(erl.validation_source),
            "is_dispatchable": (
                "yes"
                if any(getattr(erl, c) for c in ("bld", "flr", "unit", "room", "seat", "loc"))
                else "no"
            ),
            "is_active": "yes" if erl.is_active else "no",
            "latitude": _csv_safe(erl.latitude),
            "longitude": _csv_safe(erl.longitude),
            "altitude": _csv_safe(erl.altitude),
            "altitude_unit": _csv_safe(erl.altitude_unit),
            "binding_count": str(len(bindings)),
            "binding_rules": _csv_safe(" ".join(sorted({b.rule_kind for b in bindings}))),
            "notes": _csv_safe(erl.notes),
        }
        for column, _catype, _tag, _desc in CIVIC_ELEMENTS:
            record[column] = _csv_safe(getattr(erl, column, None))
        writer.writerow(record)
    return buf.getvalue()


def _identifier_for(erl: EmergencyResponseLocation, index: int) -> str:
    """A STABLE, IOS-safe civic-location identifier.

    IOS identifiers are short and may not contain spaces, and an ERL name is
    neither — so it cannot be the name.

    Derived from the ERL's own id, not from its position. A positional
    ``spatium-001`` was the first version and was documented as "stable" while
    being the opposite: adding one ERL renumbers every later stanza, so an
    operator who had already applied a previous export would be re-pointing
    live port assignments at the wrong locations the next time they pasted.

    ``index`` is kept only as the tie-break for an ERL with no id yet (an
    unsaved row in a test), because two stanzas sharing an identifier is a
    config where the second silently replaces the first.
    """
    raw = getattr(erl, "id", None)
    if raw is None:
        return f"spatium-{index:03d}"
    # First 8 hex of the UUID: 4 billion values, short enough for IOS, and
    # stable for the life of the row.
    return f"spatium-{str(raw).replace('-', '')[:8]}"


def render_ios_snippets(
    rows: list[tuple[EmergencyResponseLocation, list[ERLBinding]]],
    *,
    interface_names: dict[str, list[tuple[str, str]]] | None = None,
) -> str:
    """LLDP-MED civic-location stanzas, as text for an operator to review.

    ``interface_names`` maps an ERL id to ``(device_name, interface_name)``
    pairs, so the per-interface ``location civic-location-id`` lines can be
    emitted too. Absent, only the stanzas are produced.

    The device name is carried because ``Gi1/0/12`` exists on every switch in
    the estate: a file listing bare interface names gives an operator no way
    to tell which lines belong to the switch in front of them, and pasting the
    wrong ones mis-assigns ports to rooms. The interfaces are grouped under a
    per-device heading for the same reason.
    """
    out: list[str] = [
        "! ------------------------------------------------------------------",
        "! SpatiumDDI E911 — LLDP-MED civic-location configuration",
        f"! Generated {datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "!",
        "! GENERATED FOR REVIEW. SpatiumDDI does not configure switches and",
        "! has not applied these commands to a device. Read them, check them",
        "! against your platform's LLDP-MED location documentation, and apply",
        "! them yourself.",
        "!",
        "! A value SpatiumDDI could not express safely as an IOS argument is",
        "! omitted and listed under its stanza — it is not silently shortened,",
        "! because a room whose name was truncated is a phone in the wrong",
        "! place that looks correct.",
        "! ------------------------------------------------------------------",
        "",
    ]
    interface_names = interface_names or {}

    for index, (erl, bindings) in enumerate(rows, start=1):
        ident = _identifier_for(erl, index)
        name = _ios_safe(erl.name) or "(name not expressible)"
        out.append(f"! {name}")
        out.append(f"location civic-location identifier {ident}")

        skipped: list[str] = []
        for column, keyword in IOS_CIVIC_KEYWORDS.items():
            raw = getattr(erl, column, None)
            if raw is None or str(raw).strip() == "":
                continue
            safe = _ios_safe(raw)
            if safe is None:
                skipped.append(f"{column}={raw!r}")
                continue
            out.append(f" {keyword} {safe}")

        # Elements with no IOS keyword at all. Reported for the same reason:
        # the phone will not announce them and the operator should know.
        no_keyword = [
            column
            for column, _n, _t, _d in CIVIC_ELEMENTS
            if column not in IOS_CIVIC_KEYWORDS and getattr(erl, column, None) not in (None, "")
        ]
        out.append(" exit")

        for elin in erl.elins or []:
            safe_elin = _ios_safe(elin)
            if safe_elin is None or not safe_elin.replace("+", "").isdigit():
                skipped.append(f"elin={elin!r}")
                continue
            out.append(f"location elin-location {safe_elin} identifier {ident}")

        for device_name, ifname in interface_names.get(str(erl.id), []):
            safe_if = _ios_safe(ifname)
            if safe_if is None:
                skipped.append(f"interface={ifname!r}")
                continue
            safe_dev = _ios_safe(device_name) or "(unknown switch)"
            # Which switch. Gi1/0/12 exists on all of them.
            out.append(f"! on {safe_dev}")
            out.append(f"interface {safe_if}")
            out.append(f" location civic-location-id {ident}")
            out.append(" exit")

        if skipped:
            out.append("! OMITTED (not safely expressible as IOS arguments):")
            out.extend(f"!   {s}" for s in skipped)
        if no_keyword:
            out.append(
                "! NOT SENT (no IOS civic-location keyword exists): "
                + ", ".join(sorted(no_keyword))
            )
        out.append("")

    if len(out) <= 16:
        out.append("! No Emergency Response Locations to export.")
    return "\n".join(out) + "\n"
