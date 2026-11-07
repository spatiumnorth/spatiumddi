"""HELD — HTTP-Enabled Location Delivery, RFC 5985 (#972 Phase 1b).

The standards-track protocol a PBX, an E911 provider or a phone uses to
ask "where is this device?" and get PIDF-LO back. This is the surface that
makes the feature work with **no phone-side change**: CUCM, Cisco MPP
firmware, the Webex app, RedSky "HELD+", Intrado ERS and Bandwidth DLR all
speak it already.

Two request shapes:

* **Third-party** (RFC 6155) — the caller names the device by IP, MAC or
  LLDP chassis+port inside a ``<device>`` element. This is the PBX case,
  and it is authenticated like any other API call.
* **Self** (RFC 5985 §6) — a device asks about *itself* and carries no
  identity at all; the LIS answers from the TCP source address. That is
  Phase 2 and is off by default, because it is an unauthenticated surface.

**XML from the network is untrusted input**, and the first version of this
module got the reasoning wrong in a way worth recording. It parsed with
``xml.etree.ElementTree`` and claimed that supports "no DTD and no external
entities at all — so XXE and entity-expansion are not mitigated here, they
are unavailable". Measured: **half of that is false.** Stdlib ET refuses an
external entity (``undefined entity &x;``), so XXE really is unavailable —
but it expands INTERNAL entities happily, and a four-level billion-laughs
payload expanded to 50,000 characters. CodeQL's ``py/xml-bomb`` was right
and the docstring was wrong.

So parsing now goes through ``lxml`` with ``resolve_entities=False``, which
leaves an entity reference unexpanded instead of growing it. lxml is already
in the image (python3-saml pulls it), so this adds no dependency —
``defusedxml`` would have needed a NOTICE entry and a ``versions.json`` pin
for the same outcome.

Three layers, and the ordering is deliberate:

1. The body is **size-capped** before anything parses it.
2. A ``DOCTYPE`` declaration is **refused outright**. This was the only
   thing standing between the old parser and an expansion bomb, which is
   precisely why it is kept now that it is no longer load-bearing: a guard
   that is the sole defence is one regex away from being none.
3. The parser itself **does not resolve entities**, and has ``no_network``,
   ``load_dtd`` and ``huge_tree`` off.

Each of the three is tested against a real bomb and a real XXE payload,
because the lesson here is that reasoning about a parser's behaviour is not
the same as measuring it.

**Identity elements are matched by LOCAL NAME, not by namespace.**
Deliberate, and the reason is honesty about what has been verified: the
element set here follows RFC 6155 as far as IP and MAC, which are
unambiguous, while the exact spelling a given vendor emits for a
switch-port identity has NOT been checked against a live client. Matching
on local name means a client whose namespace differs still works, and an
element we do not recognise is reported as unsupported rather than
silently treated as "no identity given" — which would quietly answer with
the *caller's* location instead of the device's, the worst failure this
surface can have.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from lxml import etree

NS_HELD = "urn:ietf:params:xml:ns:geopriv:held"

#: 64 KiB. A locationRequest is a few hundred bytes; a megabyte of it is
#: not a client, and the cap is what makes the parser's own limits moot.
MAX_REQUEST_BYTES = 64 * 1024

#: RFC 5985 §6.3 error codes we emit.
ERROR_REQUEST_ERROR = "requestError"
ERROR_XML_ERROR = "xmlError"
ERROR_NOT_LOCATABLE = "notLocatable"
ERROR_CANNOT_PROVIDE = "cannotProvideLiType"
ERROR_LOCATION_UNKNOWN = "locationUnknown"
ERROR_GENERAL_LIS_ERROR = "generalLisError"

_DOCTYPE_RE = re.compile(rb"<!DOCTYPE", re.IGNORECASE)

#: ``locationType`` tokens we honour. ``locationURI`` is deliberately
#: absent: serving one means minting a dereferenceable, unauthenticated URL
#: that hands out a person's location to whoever holds it, and that is a
#: security decision with its own issue rather than a line of code here.
SUPPORTED_LOCATION_TYPES = frozenset({"civic", "geodetic", "any"})


class HeldError(Exception):
    """A HELD-level failure, carrying the RFC 5985 code to report."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class HeldRequest:
    """What a ``locationRequest`` asked for."""

    #: Requested types, lower-cased. Empty means the client did not say, and
    #: RFC 5985 §6.1's default is "any".
    location_types: frozenset[str]
    #: ``exact="true"`` — the client wants ONLY the types it listed.
    exact: bool
    ip: str | None = None
    mac: str | None = None
    chassis_id: str | None = None
    port_id: str | None = None

    @property
    def has_identity(self) -> bool:
        return any((self.ip, self.mac, self.chassis_id))

    @property
    def wants_civic(self) -> bool:
        return not self.location_types or bool(self.location_types & {"civic", "any"})


#: Hardened parser settings. ``resolve_entities=False`` is the one that
#: stops an expansion bomb; the rest close the neighbouring doors.
def _parser() -> etree.XMLParser:
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        huge_tree=False,
    )


def _local(tag: object) -> str:
    """The local name of a possibly-namespaced tag.

    Tolerates a non-string tag: lxml's ``iter()`` yields comments and
    processing instructions whose ``tag`` is a callable, and calling
    ``rsplit`` on one raises.
    """
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def parse_location_request(body: bytes) -> HeldRequest:
    """Parse a HELD ``locationRequest``.

    Raises ``HeldError`` with the RFC 5985 code for anything malformed.
    """
    if not body:
        raise HeldError(ERROR_REQUEST_ERROR, "empty request body")
    if len(body) > MAX_REQUEST_BYTES:
        raise HeldError(
            ERROR_REQUEST_ERROR,
            f"request larger than {MAX_REQUEST_BYTES} bytes",
        )
    if _DOCTYPE_RE.search(body):
        # Refused rather than trusted to be inert. ElementTree would reject
        # an entity reference anyway; saying no to the declaration means the
        # refusal does not depend on that remaining true.
        raise HeldError(ERROR_XML_ERROR, "a DOCTYPE declaration is not accepted")

    try:
        root = etree.fromstring(body, parser=_parser())
    except etree.XMLSyntaxError as exc:
        raise HeldError(ERROR_XML_ERROR, f"malformed XML: {exc}") from exc
    if root is None:
        raise HeldError(ERROR_XML_ERROR, "no document element")

    if _local(root.tag) != "locationRequest":
        raise HeldError(
            ERROR_REQUEST_ERROR,
            f"expected a locationRequest, got {_local(root.tag)!r}",
        )

    types: set[str] = set()
    exact = False
    ip = mac = chassis_id = port_id = None
    unsupported: list[str] = []

    for el in root.iter():
        name = _local(el.tag)
        text = (el.text or "").strip()
        if name == "locationType":
            exact = (el.get("exact") or "").strip().lower() == "true"
            # Space-separated token list, per RFC 5985 §6.1.
            types.update(t.lower() for t in text.split() if t)
        elif name == "ip":
            ip = text or None
        elif name == "mac":
            mac = text or None
        elif name in ("chassisId", "chassis-id", "chassis_id"):
            chassis_id = text or None
        elif name in ("portId", "port-id", "port_id"):
            port_id = text or None
        elif name in ("fqdn", "uri", "msisdn", "imsi", "imei", "mdn", "min", "e164"):
            # Recognised RFC 6155 identities we cannot resolve. Reported, not
            # ignored: treating one as "no identity given" would fall through
            # to the self-query path and answer with the CALLER's location
            # instead of the device's.
            unsupported.append(name)

    if unsupported and not (ip or mac or chassis_id):
        raise HeldError(
            ERROR_NOT_LOCATABLE,
            "this LIS resolves a device by ip, mac, or chassis+port; "
            f"got only {', '.join(sorted(set(unsupported)))}",
        )

    unknown_types = types - SUPPORTED_LOCATION_TYPES
    if exact and unknown_types:
        raise HeldError(
            ERROR_CANNOT_PROVIDE,
            "cannot provide " + " ".join(sorted(unknown_types)),
        )

    return HeldRequest(
        location_types=frozenset(types),
        exact=exact,
        ip=ip,
        mac=mac,
        chassis_id=chassis_id,
        port_id=port_id,
    )


def render_location_response(pidf_lo: bytes) -> bytes:
    """Wrap a PIDF-LO document in a HELD ``locationResponse``.

    The PIDF-LO is spliced in rather than re-serialised: it was built by
    ``pidf_lo.render_pidf_lo`` with its own namespace declarations, and
    re-parsing it to re-emit it would be two chances to lose them for no
    gain. The XML declaration is stripped because it may only appear once,
    at the top of the document.
    """
    inner = pidf_lo
    if inner.startswith(b"<?xml"):
        # An XML declaration may appear only once, at the very top.
        inner = inner.split(b"?>", 1)[1].lstrip()
    return b"".join(
        (
            b'<?xml version="1.0" encoding="UTF-8"?>\n',
            b'<locationResponse xmlns="',
            NS_HELD.encode(),
            b'">\n',
            inner,
            b"\n</locationResponse>\n",
        )
    )


def render_error(code: str, message: str) -> bytes:
    """An RFC 5985 §6.3 ``<error>`` document.

    ``message`` is attribute text, so ElementTree's escaping does the work
    — a parser error string can contain anything.
    """
    root = etree.Element(f"{{{NS_HELD}}}error", {"code": code}, nsmap={None: NS_HELD})
    etree.SubElement(root, f"{{{NS_HELD}}}message").text = message
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + etree.tostring(
        root, encoding="utf-8", xml_declaration=False
    )
