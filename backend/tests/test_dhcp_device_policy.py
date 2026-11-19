"""Fingerprint-driven DHCP device policies (issue #700).

The tests that matter here are the ones guarding a *silent* misfire —
a policy that renders, looks configured, and applies to the wrong
devices or to none:

* an unmatchable signature must never compile to an always-true term
* an empty vendor class must never compile to ``0x``, which Kea rejects
  whole, taking every unrelated class in the group down with it
* a signature shared with devices outside the selected classes is
  excluded unless the operator opts in
* the expression is deterministic, because it rides the bundle ETag
* nothing device-controlled reaches the config as a quoted string
* a policy that compiles to nothing is dropped rather than rendered
  testless, which in Kea means "match every packet"
* device-policy classes reach the *wire*, per the #858 lesson
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.models.dhcp_device_policy import DHCPDevicePolicy
from app.models.dhcp_fingerprint import DHCPFingerprint
from app.services.dhcp.config_bundle import build_config_bundle
from app.services.dhcp.device_policy import (
    LOW_CONFIDENCE_SCORE,
    MAX_SIGNATURE_TERMS,
    Signature,
    _term,
    build_expression,
    compile_device_policy,
    load_fingerprint_snapshot,
    option55_to_hex,
    slugify_class_name,
    text_to_hex,
)


async def _make_user(db: AsyncSession) -> tuple[User, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user, create_access_token(str(user.id))


async def _make_group_with_server(
    db: AsyncSession,
) -> tuple[DHCPServerGroup, DHCPServer]:
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(grp)
    await db.flush()
    srv = DHCPServer(
        name=f"s-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="127.0.0.1",
        port=67,
        server_group_id=grp.id,
    )
    db.add(srv)
    await db.flush()
    return grp, srv


def _fp(
    mac: str,
    opt55: str | None,
    opt60: str | None,
    klass: str | None,
    score: int | None = 90,
) -> DHCPFingerprint:
    return DHCPFingerprint(
        mac_address=mac,
        option_55=opt55,
        option_60=opt60,
        fingerbank_device_class=klass,
        fingerbank_score=score,
    )


def _policy(group_id, **kw) -> DHCPDevicePolicy:
    base = {
        "group_id": group_id,
        "name": kw.pop("name", f"p-{uuid.uuid4().hex[:6]}"),
        "class_name": kw.pop("class_name", f"spatium-device-{uuid.uuid4().hex[:6]}"),
        "device_classes": kw.pop("device_classes", ["Printer"]),
        "enabled": kw.pop("enabled", True),
    }
    base.update(kw)
    return DHCPDevicePolicy(**base)


_NO_DEVICES_WARNING = "No devices have been seen in the selected classes yet"
_UNMATCHABLE_WARNING = "in a form that can be matched"


# ── Encoding primitives ───────────────────────────────────────────


def test_option55_to_hex_encodes_decimal_csv() -> None:
    assert option55_to_hex("1,3,6,15") == "0103060F"
    assert option55_to_hex("1, 3 ,6") == "010306"


@pytest.mark.parametrize("bad", ["", None, "1,300", "1,-2", "1,x", "abc"])
def test_option55_to_hex_rejects_unusable(bad: str | None) -> None:
    """A byte outside 0-255 or a non-numeric field means the stored row is
    not a parameter-request-list. Coercing it would emit an expression that
    matches the wrong packets, so the term is dropped instead."""
    assert option55_to_hex(bad) is None


def test_text_to_hex_empty_is_none_not_empty_string() -> None:
    """``option[60].hex == 0x`` is a parse error that fails the ENTIRE Kea
    config, not just this class — verified against kea-dhcp4 3.0.3."""
    assert text_to_hex("") is None
    assert text_to_hex(None) is None
    assert text_to_hex("MSFT 5.0") == "4D53465420352E30"


def test_signature_with_nothing_to_match_is_never_rendered() -> None:
    """The single most dangerous term this compiler could emit.

    An empty term would collapse the OR into an always-true expression and
    hand the policy's option set and lease time to every device on the
    network."""
    assert _term(Signature(None, None)) is None
    assert build_expression([Signature(None, None)]) == ""


def test_absent_vendor_class_is_asserted_not_ignored() -> None:
    """A device that sent no option 60 compiles to ``not option[60].exists``.

    Ignoring the absence would widen the match to every device sharing the
    parameter-request-list, including ones that DO send a vendor class."""
    term = _term(Signature("1,3,6", None))
    assert term is not None
    assert "not option[60].exists" in term


def test_signatures_sort_when_one_lacks_an_option() -> None:
    """Regression: ``Signature`` used ``order=True``, whose generated
    ``__lt__`` compares ``None`` against ``str`` as soon as two in-class
    signatures agree on option 55 and differ on whether option 60 is
    present. That raised TypeError inside ``build_config_bundle`` — a 500
    on the agent long-poll that stops the entire group converging. Every
    earlier fixture happened to differ on option 55, which is why nothing
    caught it."""
    rows = [
        Signature("1,3,6", "HP"),
        Signature("1,3,6", None),
        Signature(None, "X"),
        Signature(None, None),
    ]
    rows.sort(key=lambda s: s.sort_key)  # must not raise
    assert len(rows) == 4


def test_lossy_decoded_vendor_class_is_refused_not_mismatched() -> None:
    """A non-UTF-8 option 60 is stored already destroyed (the fingerprint
    row decodes with errors="replace"), so re-encoding yields EF BF BD —
    bytes the device never sent. Emitting it would list the device as
    matched in the preview while the rendered class silently skipped it."""
    assert text_to_hex("Acme\ufffdPrinter") is None


def test_present_but_unencodable_option_drops_the_whole_signature() -> None:
    """ "Absent" and "present but unencodable" must not be conflated.

    The device DID send a vendor class, so falling back to
    ``not option[60].exists`` would assert the opposite of the truth and
    match a different population — devices that send this request list and
    no vendor class at all. Matching confidently and wrongly is worse than
    not matching, so the signature is dropped whole."""
    assert _term(Signature("1,3,6", "Acme\ufffdPrinter")) is None
    assert _term(Signature("1,3,junk", "HP")) is None
    assert build_expression([Signature("1,3,6", "Acme\ufffdPrinter")]) == ""

    # A genuinely absent option still compiles, asserting the absence.
    assert _term(Signature("1,3,6", None)) == (
        "(option[55].hex == 0x010306 and not option[60].exists)"
    )


def test_expression_is_deterministic_regardless_of_input_order() -> None:
    """The expression rides the config-bundle ETag. An unstable ordering
    would shift the ETag on every rebuild and make every agent in the group
    re-fetch and re-render byte-identical config."""
    a = [Signature("1,3,6", "A"), Signature("1,3", "B"), Signature("9", None)]
    key = lambda s: s.sort_key  # noqa: E731
    assert build_expression(sorted(a, key=key)) == build_expression(
        sorted(list(reversed(a)), key=key)
    )


def test_device_controlled_vendor_class_never_becomes_syntax() -> None:
    """Option 60 is chosen by the *device*. Emitting it as hex means a
    vendor class of ``' or 1--`` lands as inert bytes rather than as
    expression syntax."""
    expr = build_expression([Signature("1,3,6", "' or 1--")])
    assert "'" not in expr
    assert "or 1--" not in expr
    assert expr.count("(") == expr.count(")")


def test_slugify_class_name_is_kea_safe() -> None:
    assert slugify_class_name("IoT Quarantine / v2") == "spatium-device-IoT-Quarantine-v2"
    assert slugify_class_name("!!!") == "spatium-device-policy"


# ── Compilation semantics ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_ambiguous_signature_excluded_by_default(db_session: AsyncSession) -> None:
    """A signature emitted by devices inside AND outside the selected
    classes is not matched by default.

    This is the difference between quarantining the printers and
    quarantining the laptop that happens to share their request list."""
    grp, _ = await _make_group_with_server(db_session)
    db_session.add_all(
        [
            _fp("aa:bb:cc:00:00:01", "1,3,6", None, "Printer"),
            _fp("aa:bb:cc:00:00:02", "1,3,6", None, "Windows"),
            _fp("aa:bb:cc:00:00:03", "1,3,6,15", None, "Printer"),
        ]
    )
    policy = _policy(grp.id, device_classes=["Printer"])
    db_session.add(policy)
    await db_session.flush()

    out = await compile_device_policy(db_session, policy)

    assert Signature("1,3,6", None) in out.ambiguous
    assert Signature("1,3,6", None) not in out.signatures
    assert Signature("1,3,6,15", None) in out.signatures
    assert "aa:bb:cc:00:00:02" not in out.matched_macs
    assert any("excluded" in w for w in out.warnings)


@pytest.mark.asyncio
async def test_ambiguous_signature_included_on_explicit_opt_in(
    db_session: AsyncSession,
) -> None:
    grp, _ = await _make_group_with_server(db_session)
    db_session.add_all(
        [
            _fp("aa:bb:cc:00:01:01", "1,3,6", None, "Printer"),
            _fp("aa:bb:cc:00:01:02", "1,3,6", None, "Windows"),
        ]
    )
    policy = _policy(grp.id, device_classes=["Printer"], include_ambiguous=True)
    db_session.add(policy)
    await db_session.flush()

    out = await compile_device_policy(db_session, policy)
    assert Signature("1,3,6", None) in out.signatures
    assert not any(_NO_DEVICES_WARNING in w for w in out.warnings)


@pytest.mark.asyncio
async def test_unclassified_device_is_not_ambiguity_but_is_reported(
    db_session: AsyncSession,
) -> None:
    """A device fingerbank has not answered on is not evidence of a
    different class — excluding an otherwise-clean signature because of one
    would make the feature unusable before an API key is set. It WILL
    receive the policy, so the count is surfaced instead of buried."""
    grp, _ = await _make_group_with_server(db_session)
    db_session.add_all(
        [
            _fp("aa:bb:cc:00:02:01", "1,3,6", None, "Printer"),
            _fp("aa:bb:cc:00:02:02", "1,3,6", None, None),
        ]
    )
    policy = _policy(grp.id, device_classes=["Printer"])
    db_session.add(policy)
    await db_session.flush()

    out = await compile_device_policy(db_session, policy)
    assert Signature("1,3,6", None) in out.signatures
    assert out.ambiguous == []
    assert out.unclassified_matches == 1
    assert any("not classified" in w for w in out.warnings)


@pytest.mark.asyncio
async def test_truncation_is_reported_never_silent(db_session: AsyncSession) -> None:
    grp, _ = await _make_group_with_server(db_session)
    for i in range(MAX_SIGNATURE_TERMS + 5):
        db_session.add(
            _fp(f"aa:bb:cc:{i // 256:02x}:{i % 256:02x}:01", f"1,{i % 250 + 1},6", str(i), "IoT")
        )
    policy = _policy(grp.id, device_classes=["IoT"])
    db_session.add(policy)
    await db_session.flush()

    out = await compile_device_policy(db_session, policy)
    assert len(out.signatures) == MAX_SIGNATURE_TERMS
    assert out.truncated == 5
    assert any("cap" in w for w in out.warnings)
    assert not any(_NO_DEVICES_WARNING in w for w in out.warnings)


@pytest.mark.asyncio
async def test_override_is_rendered_and_compiled_still_reported(
    db_session: AsyncSession,
) -> None:
    """The issue requires the compiled expression stay visible so nobody
    debugs a black box — an override must not hide what we would have
    generated."""
    grp, _ = await _make_group_with_server(db_session)
    db_session.add(_fp("aa:bb:cc:00:03:01", "1,3,6", None, "Printer"))
    policy = _policy(grp.id, device_classes=["Printer"], match_override="option[55].hex == 0xDEAD")
    db_session.add(policy)
    await db_session.flush()

    out = await compile_device_policy(db_session, policy)
    assert out.expression == "option[55].hex == 0xDEAD"
    assert out.source == "override"
    assert out.signatures  # the compiled input is still reported


@pytest.mark.asyncio
async def test_policy_with_no_observations_compiles_to_nothing(
    db_session: AsyncSession,
) -> None:
    grp, _ = await _make_group_with_server(db_session)
    policy = _policy(grp.id, device_classes=["Nothing Seen Yet"])
    db_session.add(policy)
    await db_session.flush()

    out = await compile_device_policy(db_session, policy)
    assert out.expression == ""
    assert out.source == "empty"


# ── Bundle + wire ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bundle_drops_policy_that_compiles_to_nothing(
    db_session: AsyncSession,
) -> None:
    """A Kea class with no ``test`` matches EVERY packet. Rendering an
    unmatched policy testless would apply its option set and lease time to
    the whole network."""
    grp, srv = await _make_group_with_server(db_session)
    db_session.add(_policy(grp.id, device_classes=["Never Seen"]))
    await db_session.flush()

    bundle = await build_config_bundle(db_session, srv)
    assert bundle.device_policy_classes == ()


@pytest.mark.asyncio
async def test_bundle_drops_disabled_policy(db_session: AsyncSession) -> None:
    grp, srv = await _make_group_with_server(db_session)
    db_session.add(_fp("aa:bb:cc:00:04:01", "1,3,6", None, "Printer"))
    db_session.add(_policy(grp.id, device_classes=["Printer"], enabled=False))
    await db_session.flush()

    bundle = await build_config_bundle(db_session, srv)
    assert bundle.device_policy_classes == ()


@pytest.mark.asyncio
async def test_bundle_renders_matching_policy_with_lease_time(
    db_session: AsyncSession,
) -> None:
    grp, srv = await _make_group_with_server(db_session)
    db_session.add(_fp("aa:bb:cc:00:05:01", "1,3,6", None, "Printer"))
    db_session.add(
        _policy(
            grp.id,
            device_classes=["Printer"],
            class_name="spatium-device-printers",
            lease_time=600,
            options={"dns-servers": "10.0.0.53"},
        )
    )
    await db_session.flush()

    bundle = await build_config_bundle(db_session, srv)
    assert len(bundle.device_policy_classes) == 1
    cls = bundle.device_policy_classes[0]
    assert cls.name == "spatium-device-printers"
    assert cls.lease_time == 600
    assert cls.options == {"dns-servers": "10.0.0.53"}
    assert "option[55].hex" in cls.match_expression


@pytest.mark.asyncio
async def test_policy_change_moves_the_etag(db_session: AsyncSession) -> None:
    """Without this the agent's long-poll never learns the class exists."""
    grp, srv = await _make_group_with_server(db_session)
    before = (await build_config_bundle(db_session, srv)).compute_etag()

    db_session.add(_fp("aa:bb:cc:00:06:01", "1,3,6", None, "Printer"))
    db_session.add(_policy(grp.id, device_classes=["Printer"]))
    await db_session.flush()

    after = (await build_config_bundle(db_session, srv)).compute_etag()
    assert before != after


@pytest.mark.asyncio
async def test_unclassified_behind_an_excluded_signature_is_not_counted(
    db_session: AsyncSession,
) -> None:
    """Only devices the RENDERED expression reaches are reported.

    An unclassified device sharing a signature that was excluded for
    ambiguity will not receive the policy, so counting it would overstate
    the blast radius — in the one report an operator leans on to decide
    whether a quarantine is safe to switch on."""
    grp, _ = await _make_group_with_server(db_session)
    db_session.add_all(
        [
            # `1,3,6` is emitted inside AND outside the selected class, so it
            # is excluded — along with the unclassified device behind it.
            _fp("aa:bb:cc:00:07:01", "1,3,6", None, "Printer"),
            _fp("aa:bb:cc:00:07:02", "1,3,6", None, "Windows"),
            _fp("aa:bb:cc:00:07:03", "1,3,6", None, None),
            # A clean signature, with its own unclassified sharer.
            _fp("aa:bb:cc:00:07:04", "1,3,6,15", None, "Printer"),
            _fp("aa:bb:cc:00:07:05", "1,3,6,15", None, None),
        ]
    )
    policy = _policy(grp.id, device_classes=["Printer"])
    db_session.add(policy)
    await db_session.flush()

    out = await compile_device_policy(db_session, policy)

    assert Signature("1,3,6", None) in out.ambiguous
    assert out.signatures == [Signature("1,3,6,15", None)]
    # One, not two: the device behind the excluded signature does not count.
    assert out.unclassified_matches == 1


@pytest.mark.asyncio
async def test_bundle_survives_signatures_differing_only_on_absent_option(
    db_session: AsyncSession,
) -> None:
    """End-to-end guard for the sort crash: this is the shape that reached
    ``build_config_bundle`` and 500'd the agent config long-poll."""
    grp, srv = await _make_group_with_server(db_session)
    db_session.add_all(
        [
            _fp("aa:bb:cc:00:08:01", "1,3,6", "HP-Printer", "Printer"),
            _fp("aa:bb:cc:00:08:02", "1,3,6", None, "Printer"),
        ]
    )
    db_session.add(_policy(grp.id, device_classes=["Printer"]))
    await db_session.flush()

    bundle = await build_config_bundle(db_session, srv)  # must not raise
    assert len(bundle.device_policy_classes) == 1


@pytest.mark.asyncio
async def test_override_reports_the_compiled_expression_separately(
    db_session: AsyncSession,
) -> None:
    """``compiled_expression`` previously echoed the override, making the
    documented comparison impossible."""
    grp, _ = await _make_group_with_server(db_session)
    db_session.add(_fp("aa:bb:cc:00:09:01", "1,3,6", None, "Printer"))
    policy = _policy(grp.id, device_classes=["Printer"], match_override="option[55].hex == 0xDEAD")
    db_session.add(policy)
    await db_session.flush()

    out = await compile_device_policy(db_session, policy)
    assert out.expression == "option[55].hex == 0xDEAD"
    assert out.compiled_expression != out.expression
    assert "option[55].hex == 0x010306" in out.compiled_expression


@pytest.mark.asyncio
async def test_shared_snapshot_matches_a_per_policy_compile(
    db_session: AsyncSession,
) -> None:
    """The bundle passes one fingerprint snapshot to every policy so the
    store is read once per tick rather than once per policy. The hoisted
    read must not change the answer."""
    grp, _ = await _make_group_with_server(db_session)
    db_session.add_all(
        [
            _fp("aa:bb:cc:00:0a:01", "1,3,6,15", None, "Printer"),
            _fp("aa:bb:cc:00:0a:02", "1,3,6", None, "Windows"),
        ]
    )
    policy = _policy(grp.id, device_classes=["Printer"])
    db_session.add(policy)
    await db_session.flush()

    snap = await load_fingerprint_snapshot(db_session)
    assert (await compile_device_policy(db_session, policy, snapshot=snap)).expression == (
        await compile_device_policy(db_session, policy)
    ).expression


@pytest.mark.asyncio
async def test_explicit_null_on_a_not_null_field_is_422_not_500(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """``exclude_unset`` is kept so a null can CLEAR a nullable field, but
    it also let a null reach NOT NULL columns, where the blanket setattr
    turned it into an unhandled 500 on commit."""
    _, token = await _make_user(db_session)
    grp, _ = await _make_group_with_server(db_session)
    policy = _policy(grp.id, device_classes=["Printer"])
    db_session.add(policy)
    await db_session.commit()

    headers = {"Authorization": f"Bearer {token}"}
    for field_name in ("options", "enabled", "priority", "device_classes"):
        r = await client.put(
            f"/api/v1/dhcp/device-policies/{policy.id}",
            json={field_name: None},
            headers=headers,
        )
        assert r.status_code == 422, f"{field_name} -> {r.status_code}"

    # A null on a NULLABLE field still means "clear it".
    r = await client.put(
        f"/api/v1/dhcp/device-policies/{policy.id}",
        json={"lease_time": None},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["lease_time"] is None


@pytest.mark.asyncio
async def test_preview_does_not_write(db_session: AsyncSession, client: AsyncClient) -> None:
    """A GET authorised by ``read`` must not commit — it would be an
    unaudited write that maintenance mode does not gate."""
    _, token = await _make_user(db_session)
    grp, _ = await _make_group_with_server(db_session)
    policy = _policy(grp.id, device_classes=["Printer"])
    db_session.add(policy)
    await db_session.commit()
    before = policy.modified_at

    r = await client.get(
        f"/api/v1/dhcp/device-policies/{policy.id}/preview",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    await db_session.refresh(policy)
    assert policy.modified_at == before


@pytest.mark.asyncio
async def test_low_fingerbank_confidence_is_warned(db_session: AsyncSession) -> None:
    """A low score means fingerbank fell back to the MAC vendor instead of
    identifying the device — verified against a live key, where an
    unidentified Apple device came back as device_class "Hardware
    Manufacturer" at 29 while an exactly-identified print server scored 89.
    A class built from vendor fallbacks groups unrelated hardware, which is
    the wrong thing to hang a quarantine on."""
    grp, _ = await _make_group_with_server(db_session)
    db_session.add(_fp("aa:bb:cc:00:0b:01", "1,3,6", None, "Hardware Manufacturer", score=29))
    policy = _policy(grp.id, device_classes=["Hardware Manufacturer"])
    db_session.add(policy)
    await db_session.flush()

    out = await compile_device_policy(db_session, policy)
    assert out.confidence == 29
    assert any("confidence" in w for w in out.warnings)
    # Still compiles — this is advice, not a refusal. The operator may know
    # their estate better than fingerbank does.
    assert out.expression


@pytest.mark.asyncio
async def test_confident_classification_is_not_warned(
    db_session: AsyncSession,
) -> None:
    grp, _ = await _make_group_with_server(db_session)
    db_session.add(_fp("aa:bb:cc:00:0c:01", "1,3,6", None, "HP Print Server", score=89))
    policy = _policy(grp.id, device_classes=["HP Print Server"])
    db_session.add(policy)
    await db_session.flush()

    out = await compile_device_policy(db_session, policy)
    assert out.confidence == 89
    assert not any("confidence" in w for w in out.warnings)
    assert out.confidence >= LOW_CONFIDENCE_SCORE


@pytest.mark.asyncio
async def test_classes_with_no_observed_devices_warn_why_not_rendered(
    db_session: AsyncSession,
) -> None:
    """#2000: classes selected, nothing fingerprinted in them yet -> empty
    expression, not rendered. The warning says why, and it is absent when
    signatures exist, when a manual match is set, and when the empty result is
    the ambiguous exclusion (which has its own message)."""
    grp, _ = await _make_group_with_server(db_session)

    # Only a device in another class: nothing in "Printer".
    db_session.add(_fp("aa:bb:cc:00:00:09", "9,9", None, "Windows"))
    empty = _policy(grp.id, device_classes=["Printer"])
    manual = _policy(grp.id, device_classes=["Printer"], match_override="option[60].hex == 0x74")
    db_session.add_all([empty, manual])
    await db_session.flush()

    out = await compile_device_policy(db_session, empty)
    assert not out.expression
    assert any(_NO_DEVICES_WARNING in w for w in out.warnings)

    out_manual = await compile_device_policy(db_session, manual)
    assert out_manual.expression
    assert not any(_NO_DEVICES_WARNING in w for w in out_manual.warnings)

    # Signatures exist -> compiles, no warning.
    db_session.add(_fp("aa:bb:cc:00:00:01", "1,3,6", None, "Printer"))
    await db_session.flush()
    out_seen = await compile_device_policy(db_session, empty)
    assert out_seen.expression
    assert not any(_NO_DEVICES_WARNING in w for w in out_seen.warnings)


@pytest.mark.asyncio
async def test_all_ambiguous_keeps_its_own_warning_not_the_no_devices_one(
    db_session: AsyncSession,
) -> None:
    grp, _ = await _make_group_with_server(db_session)
    db_session.add_all(
        [
            _fp("aa:bb:cc:00:00:01", "1,3,6", None, "Printer"),
            _fp("aa:bb:cc:00:00:02", "1,3,6", None, "Windows"),
        ]
    )
    policy = _policy(grp.id, device_classes=["Printer"])
    db_session.add(policy)
    await db_session.flush()

    out = await compile_device_policy(db_session, policy)
    assert not out.expression
    assert any("excluded" in w for w in out.warnings)
    assert not any(_NO_DEVICES_WARNING in w for w in out.warnings)


@pytest.mark.asyncio
async def test_in_class_devices_with_unmatchable_signatures_are_not_called_unseen(
    db_session: AsyncSession,
) -> None:
    """#2000 boundary: a device in the selected class that sent neither option
    55 nor 60 is skipped by _term, so the result is empty — but devices WERE
    seen, and "no devices have been seen" would be false."""
    grp, _ = await _make_group_with_server(db_session)
    db_session.add(_fp("aa:bb:cc:00:00:01", None, None, "Printer"))
    policy = _policy(grp.id, device_classes=["Printer"])
    db_session.add(policy)
    await db_session.flush()

    out = await compile_device_policy(db_session, policy)
    assert not out.expression
    assert not any(_NO_DEVICES_WARNING in w for w in out.warnings)
    assert any(_UNMATCHABLE_WARNING in w and w.startswith("1 device") for w in out.warnings)


@pytest.mark.asyncio
async def test_no_devices_warning_boundaries(db_session: AsyncSession) -> None:
    """#2000 boundaries: an unclassified device sharing nothing with the class
    does not count as seen in it; a disabled policy still gets the (true)
    warning; and no classes selected gets only its own warning, never both."""
    grp, _ = await _make_group_with_server(db_session)
    db_session.add(_fp("aa:bb:cc:00:00:01", "1,3,6", None, None))
    disabled = _policy(grp.id, device_classes=["Printer"], enabled=False)
    no_classes = _policy(grp.id, device_classes=[])
    db_session.add_all([disabled, no_classes])
    await db_session.flush()

    out = await compile_device_policy(db_session, disabled)
    assert not out.expression
    assert out.unclassified_matches == 0
    assert any(_NO_DEVICES_WARNING in w for w in out.warnings)
    assert not any("renders once" in w for w in out.warnings)

    out_none = await compile_device_policy(db_session, no_classes)
    assert not any(_NO_DEVICES_WARNING in w for w in out_none.warnings)
    assert not any(_UNMATCHABLE_WARNING in w for w in out_none.warnings)
    assert any("No device classes selected" in w for w in out_none.warnings)


@pytest.mark.asyncio
async def test_manual_match_only_policy_is_not_called_unrendered(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """#1992: no classes + a manual match IS rendered, so neither the compile
    warnings nor the REST preview may say it matches nothing / is not
    rendered. With neither classes nor a match the warning still applies."""
    _, token = await _make_user(db_session)
    grp, _ = await _make_group_with_server(db_session)
    manual = _policy(grp.id, device_classes=[], match_override="option[60].hex == 0x74657374")
    bare = _policy(grp.id, device_classes=[])
    db_session.add_all([manual, bare])
    await db_session.commit()

    out = await compile_device_policy(db_session, manual)
    assert out.expression
    assert not any("matches nothing" in w for w in out.warnings)
    r = await client.get(
        f"/api/v1/dhcp/device-policies/{manual.id}/preview",
        headers={"Authorization": f"Bearer {token}"},
    )
    body = r.json()
    assert body["renders"] is True
    assert not any("not rendered and" in w or "matches nothing" in w for w in body["warnings"])

    out_bare = await compile_device_policy(db_session, bare)
    assert any("matches nothing and is not rendered" in w for w in out_bare.warnings)
    assert not out_bare.expression

    # A whitespace-only match is no match: the warning and an empty
    # expression (renders=False) must still agree.
    blank = _policy(grp.id, device_classes=[], match_override="   ")
    out_blank = await compile_device_policy(db_session, blank)
    assert not out_blank.expression
    assert any("matches nothing and is not rendered" in w for w in out_blank.warnings)


@pytest.mark.asyncio
async def test_disabled_policy_manual_match_is_not_called_in_force_2753(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """#2753: the bundle omits a disabled policy, so its preview must not say
    the manual match is in force; an enabled one still does."""
    _, token = await _make_user(db_session)
    grp, _ = await _make_group_with_server(db_session)
    expr = "option[60].hex == 0x78702d6e6f6e65"
    off = _policy(grp.id, device_classes=[], match_override=expr, enabled=False)
    on = _policy(grp.id, device_classes=[], match_override=expr, enabled=True)
    db_session.add_all([off, on])
    await db_session.commit()

    hdr = {"Authorization": f"Bearer {token}"}
    r_off = (await client.get(f"/api/v1/dhcp/device-policies/{off.id}/preview", headers=hdr)).json()
    r_on = (await client.get(f"/api/v1/dhcp/device-policies/{on.id}/preview", headers=hdr)).json()
    assert r_off["renders"] is False
    assert r_off["expression"] == expr
    assert not any("in force" in w for w in r_off["warnings"])
    assert any("disabled" in w for w in r_off["warnings"])
    assert r_on["renders"] is True
    assert any("in force" in w for w in r_on["warnings"])

    # The bundle really omits the disabled policy.
    srv = await _server_of(db_session, grp.id)
    bundle = await build_config_bundle(db_session, srv)
    names = {c.name for c in bundle.device_policy_classes}
    assert on.class_name in names and off.class_name not in names


async def _server_of(db: AsyncSession, group_id) -> DHCPServer:
    from sqlalchemy import select

    return (
        (await db.execute(select(DHCPServer).where(DHCPServer.server_group_id == group_id)))
        .scalars()
        .first()
    )
