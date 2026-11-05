"""HELD + PIDF-LO (#972 Phase 1b) and the device self-query (Phase 2).

These assert on the **rendered XML** and on the refusals, because that is
what a PBX consumes and what an attacker probes. The structural claims
(well-formedness, namespaces, element naming, wire order, escaping,
lat-before-lon) are verifiable here; **interop with a live CUCM / RedSky /
Intrado endpoint is NOT**, and neither the code nor the docs claim it is.

The refusal tests carry most of the weight. An unauthenticated endpoint
that answers "which room is the device at this address in" has exactly one
catastrophic failure — answering about a device the caller merely named —
and three of the cases below exist to pin that shut.

HOW TO RUN:
    make test-one T=tests/test_e911_held.py
"""

from __future__ import annotations

import uuid
from xml.etree import ElementTree as ET

import pytest
from lxml import etree
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.e911 import EmergencyResponseLocation, ERLBinding
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.ownership import Site
from app.services.e911 import held as held_mod
from app.services.e911.held import (
    ERROR_CANNOT_PROVIDE,
    ERROR_NOT_LOCATABLE,
    ERROR_REQUEST_ERROR,
    ERROR_XML_ERROR,
    HeldError,
    parse_location_request,
    render_error,
    render_location_response,
)
from app.services.e911.pidf_lo import (
    NS_CIVIC,
    NS_GEOPRIV,
    NS_GML,
    NS_PIDF,
    PIDF_ELEMENT_ORDER,
    SRS_NAME,
    render_pidf_lo,
)

HELD_NS = "urn:ietf:params:xml:ns:geopriv:held"


def _erl(**kw) -> EmergencyResponseLocation:
    base = dict(
        name=f"erl-{uuid.uuid4().hex[:8]}",
        country="US",
        a1="NY",
        a3="New York",
        rd="Broadway",
        hno="1234",
        bld="A",
        flr="3",
        room="312",
    )
    base.update(kw)
    return EmergencyResponseLocation(**base)


# ══════════════════════════════════════════════════════════════════════
# PIDF-LO rendering
# ══════════════════════════════════════════════════════════════════════


def test_the_document_is_well_formed_and_uses_the_right_namespaces() -> None:
    doc = render_pidf_lo(_erl(), entity="pres:ip:10.20.3.44", rule_matched="subnet")
    root = ET.fromstring(doc)
    assert root.tag == f"{{{NS_PIDF}}}presence"
    assert root.get("entity") == "pres:ip:10.20.3.44"
    assert root.find(f".//{{{NS_GEOPRIV}}}geopriv") is not None
    assert root.find(f".//{{{NS_CIVIC}}}civicAddress") is not None


def test_only_the_elements_that_are_set_are_emitted() -> None:
    """An empty `<cl:ROOM/>` is a claim that the room is the empty string,
    and a consumer reasonably renders it as a room."""
    doc = render_pidf_lo(_erl(room=None, seat=None), entity="pres:x", rule_matched="subnet")
    root = ET.fromstring(doc)
    civic = root.find(f".//{{{NS_CIVIC}}}civicAddress")
    assert civic is not None
    tags = [c.tag.rsplit("}", 1)[1] for c in civic]
    assert "ROOM" not in tags and "SEAT" not in tags
    assert "FLR" in tags


def test_elements_are_emitted_in_the_rfc_5139_schema_order() -> None:
    """A consumer validating against the published schema rejects
    out-of-order children of an ``xs:sequence``. Column-declaration order is
    NOT that order — see PIDF_ELEMENT_ORDER."""
    erl = _erl(sts="Avenue", pc="10001", unit="2", loc="east wing", nam="Acme")
    doc = render_pidf_lo(erl, entity="pres:x", rule_matched="subnet")
    civic = ET.fromstring(doc).find(f".//{{{NS_CIVIC}}}civicAddress")
    assert civic is not None
    emitted = [c.tag.rsplit("}", 1)[1] for c in civic]
    expected = [t for t in PIDF_ELEMENT_ORDER if t in emitted]
    assert emitted == expected, "civic children are not in schema order"


def test_pidf_order_covers_every_civic_element() -> None:
    """Two lists describing one thing, pinned to each other — #878. An
    element missing from the wire order would silently never be sent."""
    from app.models.e911 import CIVIC_ELEMENTS

    tags = {tag for _c, _n, tag, _d in CIVIC_ELEMENTS}
    assert tags == set(PIDF_ELEMENT_ORDER)


def test_xml_special_characters_are_escaped() -> None:
    """Operator free text reaches `<cl:LOC>`; an unescaped `&` makes the
    whole document unparseable, which a consumer reports as "no location"."""
    doc = render_pidf_lo(
        _erl(loc='east wing & <reception> "main"'), entity="pres:x", rule_matched="subnet"
    )
    root = ET.fromstring(doc)  # would raise if escaping were wrong
    loc = root.find(f".//{{{NS_CIVIC}}}LOC")
    assert loc is not None and loc.text == 'east wing & <reception> "main"'


def test_a_point_is_latitude_then_longitude() -> None:
    """EPSG:4326 axis order. The other way round parses perfectly and puts
    a Manhattan address in the Southern Ocean."""
    erl = _erl()
    erl.latitude = 40.748817
    erl.longitude = -73.985428
    doc = render_pidf_lo(erl, entity="pres:x", rule_matched="subnet")
    point = ET.fromstring(doc).find(f".//{{{NS_GML}}}Point")
    assert point is not None and point.get("srsName") == SRS_NAME
    pos = point.find(f"{{{NS_GML}}}pos")
    assert pos is not None and pos.text is not None
    lat, lon = pos.text.split()
    assert lat.startswith("40.7") and lon.startswith("-73.9")


def test_no_point_element_when_there_are_no_coordinates() -> None:
    doc = render_pidf_lo(_erl(), entity="pres:x", rule_matched="subnet")
    assert ET.fromstring(doc).find(f".//{{{NS_GML}}}Point") is None


@pytest.mark.parametrize(
    ("rule", "method"),
    [
        ("switch_port", "Wiremap"),
        ("wireless_ap", "Wiremap"),
        ("subnet", "Manual"),
        ("site_default", "Manual"),
        ("mac", "Manual"),
        (None, "Manual"),
    ],
)
def test_the_method_token_reflects_how_the_location_was_determined(
    rule: str | None, method: str
) -> None:
    """RFC 4119 registers these, and a consumer treats them differently:
    `Wiremap` means somebody traced a cable, `Manual` means it was typed.
    Sending `Wiremap` for a subnet rule would overstate what we know."""
    doc = render_pidf_lo(_erl(), entity="pres:x", rule_matched=rule)
    el = ET.fromstring(doc).find(f".//{{{NS_GEOPRIV}}}method")
    assert el is not None and el.text == method


def test_retransmission_is_refused() -> None:
    """This is the location of a person at a desk. A 911 path needs no
    onward distribution rights, and `yes` would grant every recipient
    permission we have no business granting."""
    doc = render_pidf_lo(_erl(), entity="pres:x", rule_matched="subnet")
    root = ET.fromstring(doc)
    el = root.find(".//{urn:ietf:params:xml:ns:pidf:geopriv10:basicPolicy}retransmission-allowed")
    assert el is not None and el.text == "no"


def test_the_response_carries_exactly_one_xml_declaration() -> None:
    """An XML declaration may appear only at the top of a document. Two of
    them is a parse error, i.e. the client sees no location at all."""
    wrapped = render_location_response(render_pidf_lo(_erl(), entity="pres:x"))
    assert wrapped.count(b"<?xml") == 1
    root = ET.fromstring(wrapped)
    assert root.tag == f"{{{HELD_NS}}}locationResponse"
    assert root.find(f"{{{NS_PIDF}}}presence") is not None


# ══════════════════════════════════════════════════════════════════════
# HELD request parsing — the untrusted-input surface
# ══════════════════════════════════════════════════════════════════════


def _req(inner: str, attrs: str = "") -> bytes:
    return (
        f'<?xml version="1.0"?><locationRequest xmlns="{HELD_NS}"{attrs}>'
        f"{inner}</locationRequest>"
    ).encode()


def test_an_ip_identity_is_parsed() -> None:
    r = parse_location_request(
        _req('<locationType>civic</locationType><device><ip v="4">10.20.3.44</ip></device>')
    )
    assert r.ip == "10.20.3.44"
    assert r.has_identity and r.wants_civic


def test_a_mac_identity_is_parsed() -> None:
    r = parse_location_request(_req("<device><mac>aa:bb:cc:11:22:33</mac></device>"))
    assert r.mac == "aa:bb:cc:11:22:33"


def test_a_chassis_and_port_identity_is_parsed() -> None:
    r = parse_location_request(
        _req("<device><chassisId>aa:bb:cc:11:22:33</chassisId><portId>Gi3/0/12</portId></device>")
    )
    assert r.chassis_id == "aa:bb:cc:11:22:33"
    assert r.port_id == "Gi3/0/12"


def test_identities_are_matched_by_local_name_not_namespace() -> None:
    """Deliberate. The element set follows RFC 6155 for ip and mac, which are
    unambiguous; the namespace a given vendor puts them in has not been
    verified against a live client, so matching on local name means a client
    whose namespace differs still works."""
    body = (
        f'<locationRequest xmlns="{HELD_NS}">'
        '<d:device xmlns:d="urn:example:vendor"><d:ip>10.20.3.44</d:ip></d:device>'
        "</locationRequest>"
    ).encode()
    assert parse_location_request(body).ip == "10.20.3.44"


def test_a_doctype_is_refused() -> None:
    """Refused rather than trusted to be inert, so the refusal does not
    depend on ElementTree continuing to reject entity references."""
    body = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE lr [<!ENTITY x "y">]>'
        b'<locationRequest xmlns="' + HELD_NS.encode() + b'"/>'
    )
    with pytest.raises(HeldError) as e:
        parse_location_request(body)
    assert e.value.code == ERROR_XML_ERROR


def _bomb(levels: int = 4, width: int = 10) -> bytes:
    """A billion-laughs payload, built rather than pasted so the growth
    factor is visible: ``width ** levels`` copies of a 50-byte string."""
    decls = [b'<!ENTITY e0 "' + b"a" * 50 + b'">']
    for i in range(1, levels):
        decls.append(f'<!ENTITY e{i} "'.encode() + (f"&e{i - 1};".encode() * width) + b'">')
    return (
        b'<?xml version="1.0"?><!DOCTYPE lolz [' + b"".join(decls) + b"]>"
        b"<locationRequest>&e" + str(levels - 1).encode() + b";</locationRequest>"
    )


def test_an_entity_expansion_bomb_is_refused() -> None:
    """The billion-laughs shape, refused at the DOCTYPE gate."""
    with pytest.raises(HeldError) as e:
        parse_location_request(_bomb())
    assert e.value.code == ERROR_XML_ERROR


def test_the_parser_itself_does_not_expand_entities() -> None:
    """The finding that mattered, and the reason this test exists.

    The first version of this module parsed with stdlib ElementTree and its
    docstring claimed that supports "no DTD and no external entities at all —
    so XXE and entity-expansion are not mitigated here, they are unavailable".
    Measured, half of that was false: ET refuses an EXTERNAL entity but
    expands INTERNAL ones, and a four-level bomb expanded to 50,000
    characters. CodeQL's ``py/xml-bomb`` was right; the docstring was wrong.

    So this bypasses the DOCTYPE guard entirely and goes at the parser
    directly. A guard that is the sole defence is one regex away from being
    none, and the whole point of moving to lxml with
    ``resolve_entities=False`` was to stop relying on it.
    """
    from app.services.e911.held import _parser

    root = etree.fromstring(_bomb(), parser=_parser())
    # The entity reference is LEFT UNEXPANDED rather than grown.
    assert len(root.text or "") < 100, "the parser expanded an entity bomb"


def test_the_parser_itself_refuses_an_external_entity() -> None:
    """XXE, also at the parser rather than through the guard. ``no_network``
    and ``resolve_entities=False`` both bear on this."""
    from app.services.e911.held import _parser

    xxe = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        b"<locationRequest>&x;</locationRequest>"
    )
    root = etree.fromstring(xxe, parser=_parser())
    assert "root:" not in (root.text or ""), "the parser read a local file"
    assert len(root.text or "") < 100


def test_an_oversized_body_is_refused_before_parsing() -> None:
    big = b"<locationRequest>" + b"x" * (held_mod.MAX_REQUEST_BYTES + 1) + b"</locationRequest>"
    with pytest.raises(HeldError) as e:
        parse_location_request(big)
    assert e.value.code == ERROR_REQUEST_ERROR


@pytest.mark.parametrize("body", [b"", b"not xml at all", b"<unclosed>"])
def test_malformed_input_is_a_held_error_not_a_crash(body: bytes) -> None:
    with pytest.raises(HeldError):
        parse_location_request(body)


def test_the_wrong_root_element_is_refused() -> None:
    with pytest.raises(HeldError) as e:
        parse_location_request(f'<somethingElse xmlns="{HELD_NS}"/>'.encode())
    assert e.value.code == ERROR_REQUEST_ERROR


def test_a_recognised_but_unresolvable_identity_is_reported_not_ignored() -> None:
    """THE important parse case. Treating an `<msisdn>` as "no identity
    given" would fall through to the self-query path and answer with the
    CALLER's location instead of the device's — a perfectly-formed answer
    about the wrong device."""
    with pytest.raises(HeldError) as e:
        parse_location_request(_req("<device><msisdn>447700900000</msisdn></device>"))
    assert e.value.code == ERROR_NOT_LOCATABLE
    assert "msisdn" in e.value.message


def test_an_unresolvable_identity_alongside_a_usable_one_is_fine() -> None:
    r = parse_location_request(
        _req("<device><msisdn>447700900000</msisdn><ip>10.20.3.44</ip></device>")
    )
    assert r.ip == "10.20.3.44"


def test_exact_with_an_unsupported_location_type_is_refused() -> None:
    r = _req('<locationType exact="true">civic</locationType><device><ip>1.2.3.4</ip></device>')
    assert parse_location_request(r).exact is True
    with pytest.raises(HeldError) as e:
        parse_location_request(_req('<locationType exact="true">locationURI</locationType>'))
    assert e.value.code == ERROR_CANNOT_PROVIDE


def test_a_location_uri_request_is_not_silently_honoured() -> None:
    """Serving one means minting a dereferenceable unauthenticated URL that
    hands out a person's location to whoever holds it. Not supported, and
    saying so beats answering with civic data the client did not ask for."""
    from app.services.e911.held import SUPPORTED_LOCATION_TYPES

    assert "locationuri" not in {t.lower() for t in SUPPORTED_LOCATION_TYPES}


def test_an_error_document_escapes_its_message() -> None:
    doc = render_error(ERROR_XML_ERROR, 'bad char & "<here>"')
    root = ET.fromstring(doc)
    assert root.get("code") == ERROR_XML_ERROR
    msg = root.find(f"{{{HELD_NS}}}message")
    assert msg is not None and msg.text == 'bad char & "<here>"'


# ══════════════════════════════════════════════════════════════════════
# The HTTP surface — and the refusals that make it safe
# ══════════════════════════════════════════════════════════════════════

HELD_CT = {"Content-Type": "application/held+xml"}


async def _estate_with_location(db: AsyncSession) -> tuple[str, str]:
    """A voice subnet with an ERL bound to it. Returns (ip, room)."""
    site = Site(name=f"hq-{uuid.uuid4().hex[:6]}", kind="office")
    db.add(site)
    await db.flush()
    space = IPSpace(name=f"held-{uuid.uuid4().hex[:8]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.77.0.0/16", name="b")
    db.add(block)
    await db.flush()
    octet = uuid.uuid4().int % 250
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network=f"10.77.{octet}.0/24",
        name=f"voice-{octet}",
        subnet_role="voice",
        site_id=site.id,
    )
    db.add(subnet)
    await db.flush()
    ip = f"10.77.{octet}.44"
    db.add(IPAddress(subnet_id=subnet.id, address=ip, status="allocated"))
    erl = _erl(room="312")
    db.add(erl)
    await db.flush()
    db.add(ERLBinding(erl_id=erl.id, rule_kind="subnet", subnet_id=subnet.id))
    await db.commit()
    return ip, "312"


@pytest.mark.asyncio
async def test_a_third_party_request_returns_pidf_lo(client, db_session) -> None:
    from tests.test_network_api import _make_admin

    _user, token = await _make_admin(db_session)
    ip, room = await _estate_with_location(db_session)
    res = await client.post(
        "/held",
        content=_req(f"<locationType>civic</locationType><device><ip>{ip}</ip></device>"),
        headers={**HELD_CT, "Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200, res.text
    assert res.headers["content-type"].startswith("application/held+xml")
    root = ET.fromstring(res.content)
    assert root.tag == f"{{{HELD_NS}}}locationResponse"
    assert root.find(f".//{{{NS_CIVIC}}}ROOM").text == room
    # The resolver's verdict on the wire: PIDF-LO has nowhere to say "this
    # is a fallback answer", and dropping the distinction would undo the
    # freshness rule.
    assert res.headers["X-SpatiumDDI-Confidence"] == "observed"
    assert res.headers["X-SpatiumDDI-Rule"] == "subnet"


@pytest.mark.asyncio
async def test_a_third_party_request_with_no_identity_is_refused(client, db_session) -> None:
    """THE load-bearing refusal. RFC 5985's default is to answer from the
    requester's own address, so falling through would hand a PBX the
    location of its own server in response to a question about a phone — a
    perfectly-formed answer that is completely wrong."""
    from tests.test_network_api import _make_admin

    _user, token = await _make_admin(db_session)
    await _estate_with_location(db_session)
    res = await client.post(
        "/held",
        content=_req("<locationType>civic</locationType>"),
        headers={**HELD_CT, "Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 400
    root = ET.fromstring(res.content)
    assert root.get("code") == ERROR_NOT_LOCATABLE
    assert "self-query" in (root.find(f"{{{HELD_NS}}}message").text or "")


@pytest.mark.asyncio
async def test_an_unknown_device_is_404_location_unknown(client, db_session) -> None:
    """RFC 5985 §6.3, and what a provider's retry logic expects. An empty
    200 would read as "this device has no location by design"."""
    from tests.test_network_api import _make_admin

    _user, token = await _make_admin(db_session)
    res = await client.post(
        "/held",
        content=_req("<device><ip>192.0.2.99</ip></device>"),
        headers={**HELD_CT, "Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 404
    assert ET.fromstring(res.content).get("code") == "locationUnknown"


@pytest.mark.asyncio
async def test_held_requires_authentication(client, db_session) -> None:
    await _estate_with_location(db_session)
    res = await client.post(
        "/held", content=_req("<device><ip>10.77.0.44</ip></device>"), headers=HELD_CT
    )
    assert res.status_code in (401, 403)


@pytest.mark.asyncio
async def test_the_self_query_is_404_while_disabled(client, db_session) -> None:
    """A 404 rather than a 403, so a disabled surface does not advertise
    itself to a scanner."""
    # The estate exists so the 404 is about the FEATURE being off, not about
    # there being nothing to find. Its return value is deliberately unused.
    await _estate_with_location(db_session)
    res = await client.post("/held/self", content=_req(""), headers=HELD_CT)
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_the_self_query_ignores_a_body_supplied_identity(
    client, db_session, monkeypatch
) -> None:
    """The whole security argument for this endpoint. Honouring a
    body-supplied <ip> would turn an unauthenticated route into a location
    oracle for the entire estate."""
    from app.config import settings

    monkeypatch.setattr(settings, "e911_self_query_enabled", True)
    monkeypatch.setattr(
        "app.api.v1.e911.held_router.e911_self_query_rate_limited",
        _never_limited,
    )
    ip, _room = await _estate_with_location(db_session)
    # Ask about a real, locatable address. The test client's source address
    # is not it, so the answer must NOT be that location.
    res = await client.post(
        "/held/self",
        content=_req(f"<device><ip>{ip}</ip></device>"),
        headers=HELD_CT,
    )
    # Either "no location for the caller's own address" or a location that
    # is not the one named in the body — never the named one.
    if res.status_code == 200:
        room = ET.fromstring(res.content).find(f".//{{{NS_CIVIC}}}ROOM")
        assert room is None or room.text != "312"
    else:
        assert res.status_code == 404


async def _never_limited(_ip):
    return False


@pytest.mark.asyncio
async def test_the_self_query_is_rate_limited_fail_closed(client, db_session, monkeypatch) -> None:
    """Unlike the login throttle, this one IS the protection: behind it is an
    unauthenticated endpoint answering "which room is the device at this
    address in"."""
    from app.config import settings

    monkeypatch.setattr(settings, "e911_self_query_enabled", True)

    async def _always_limited(_ip):
        return True

    monkeypatch.setattr("app.api.v1.e911.held_router.e911_self_query_rate_limited", _always_limited)
    res = await client.post("/held/self", content=_req(""), headers=HELD_CT)
    assert res.status_code == 429


@pytest.mark.asyncio
async def test_every_held_answer_writes_a_resolution_log_row(client, db_session) -> None:
    """The protocol is different; the fact that somebody asked where a person
    sits is not."""
    from sqlalchemy import func, select

    from app.models.e911 import E911ResolutionLog
    from tests.test_network_api import _make_admin

    _user, token = await _make_admin(db_session)
    ip, _room = await _estate_with_location(db_session)
    before = (await db_session.execute(select(func.count(E911ResolutionLog.id)))).scalar_one()
    await client.post(
        "/held",
        content=_req(f"<device><ip>{ip}</ip></device>"),
        headers={**HELD_CT, "Authorization": f"Bearer {token}"},
    )
    after = (await db_session.execute(select(func.count(E911ResolutionLog.id)))).scalar_one()
    assert after == before + 1


# ══════════════════════════════════════════════════════════════════════
# /code-review round 3
# ══════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_exact_geodetic_against_a_civic_only_erl_is_refused(client, db_session) -> None:
    """RFC 5985 §6.1: with exact="true" the client wants ONLY the types it
    listed. The first version parsed `locationType` and `exact` and read
    neither, so a caller asking exactly for geodetic got a 200 carrying civic
    data it had explicitly said it could not use."""
    from tests.test_network_api import _make_admin

    _user, token = await _make_admin(db_session)
    ip, _room = await _estate_with_location(db_session)  # no coordinates
    res = await client.post(
        "/held",
        content=_req(
            f'<locationType exact="true">geodetic</locationType>' f"<device><ip>{ip}</ip></device>"
        ),
        headers={**HELD_CT, "Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 400
    assert ET.fromstring(res.content).get("code") == ERROR_CANNOT_PROVIDE


@pytest.mark.asyncio
async def test_exact_civic_is_still_answered(client, db_session) -> None:
    """Control: the refusal is about a type we cannot supply, not about
    `exact` itself."""
    from tests.test_network_api import _make_admin

    _user, token = await _make_admin(db_session)
    ip, room = await _estate_with_location(db_session)
    res = await client.post(
        "/held",
        content=_req(
            f'<locationType exact="true">civic</locationType>' f"<device><ip>{ip}</ip></device>"
        ),
        headers={**HELD_CT, "Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    assert ET.fromstring(res.content).find(f".//{{{NS_CIVIC}}}ROOM").text == room


def test_held_is_exempt_from_maintenance_mode() -> None:
    """A change window must not stop answering "which room is this phone in".
    A PBX asking on behalf of a 911 call is the one caller that cannot wait for
    the window to close — and `GET /api/v1/e911/location` kept working
    throughout, so 503ing only the standards-track path was incoherent as well
    as dangerous."""
    from app.core.maintenance_mode import EXEMPT_PREFIXES

    assert "/held" in EXEMPT_PREFIXES


def test_nginx_proxies_held_in_both_templates() -> None:
    """Without its own location block `/held` falls through to the SPA
    `location /` and a PBX asking where a phone is gets index.html with a 200 —
    unreachable through the shipped frontend on compose, Helm and the appliance
    alike.

    Skipped rather than failed when the repo root is absent: the api image
    contains only ``backend/``, so this can only run from a full checkout,
    which is what CI has. A skip here is honest; a pass would not be.
    """
    import pathlib as _p

    root = _p.Path(__file__).resolve().parents[2]
    templates = [
        root / "frontend" / "default.conf.template",
        root / "charts" / "spatiumddi" / "templates" / "frontend-tls-config.yaml",
    ]
    if not all(t.is_file() for t in templates):
        pytest.skip("nginx templates are outside the api image; run from a checkout")
    for t in templates:
        assert "location /held" in t.read_text(), str(t)


def test_an_unknown_client_address_is_a_400_not_a_429(monkeypatch) -> None:
    """The throttle fails closed, so asking it first answered "slow down" for a
    request that can never succeed however slowly it is retried — and made the
    accurate message unreachable. Structural, because the ASGI test client
    always supplies a client address."""
    import inspect

    from app.api.v1.e911 import held_router

    src = inspect.getsource(held_router.held_self_query)
    unknown = src.index("could not determine the requesting address")
    throttled = src.index("e911_self_query_rate_limited")
    assert unknown < throttled, "the throttle still runs before the address check"


@pytest.mark.asyncio
async def test_held_over_the_log_budget_answers_without_a_trail_row(client, db_session) -> None:
    """#3514: past the per-caller budget the lookup is answered, not logged."""
    from unittest.mock import patch

    from sqlalchemy import func, select

    from app.models.e911 import E911ResolutionLog
    from tests.test_network_api import _make_admin

    _user, token = await _make_admin(db_session)
    ip, _room = await _estate_with_location(db_session)

    async def count() -> int:
        return (
            await db_session.execute(select(func.count()).select_from(E911ResolutionLog))
        ).scalar_one()

    before = await count()
    body = _req(f"<locationType>civic</locationType><device><ip>{ip}</ip></device>")
    hdr = {**HELD_CT, "Authorization": f"Bearer {token}"}
    with patch("app.api.v1.e911.held_router.e911_lookup_log_rate_limited", return_value=True):
        res = await client.post("/held", content=body, headers=hdr)
    assert res.status_code == 200, res.text
    assert await count() == before
    with patch("app.api.v1.e911.held_router.e911_lookup_log_rate_limited", return_value=False):
        res = await client.post("/held", content=body, headers=hdr)
    assert res.status_code == 200
    assert await count() == before + 1
