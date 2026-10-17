"""#1980 — a Windows per-value delete removes only the matching record.

A DNS pool member removal is a ``delete`` op with ``rrset_action=
"delete_value"`` and no resolved RRset (``stamp_rrsets_for_ops`` skips those
on purpose). The Windows driver then rendered ``Get-… | Remove-…`` over the
whole ``(name, type)``, so removing one member deleted every healthy one.
Pinned on the rendered PowerShell, singular and batched.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from app.drivers._winrm import MAX_ENCODED_COMMAND, encoded_command_len
from app.drivers.dns.base import RecordChange, RecordData, RRsetData, RRsetMember
from app.drivers.dns.windows import _pack_record_chunks, _ps_apply_record, _ps_apply_record_batch
from tests.test_dns_agentless_rrset import _batch_payload


def _del(value: str, rtype: str = "A", *, rrset: RRsetData | None = None) -> RecordChange:
    return RecordChange(
        op="delete",
        zone_name="example.com.",
        record=RecordData(name="pool", record_type=rtype, value=value, ttl=60),
        target_serial=1,
        rrset=rrset,
    )


def test_singular_a_delete_filters_on_the_value() -> None:
    script = _ps_apply_record(_del("10.0.0.2"))
    assert "Where-Object" in script
    # Compared as IPAddress (a byte compare), not as text.
    assert "([ipaddress]\"$($_.RecordData.IPv4Address)\").Equals([ipaddress]'10.0.0.2')" in script
    # The removal still happens only after the filter, behind the zone guard.
    assert script.index("Where-Object") < script.index("Remove-DnsServerResourceRecord")
    assert "Get-DnsServerZone" in script


def test_singular_aaaa_value_is_canonicalised() -> None:
    script = _ps_apply_record(_del("2001:DB8:0:0:0:0:0:1", "AAAA"))
    assert "RecordData.IPv6Address" in script
    assert "Equals([ipaddress]'2001:db8::1')" in script


def test_singular_hostname_types_compare_without_trailing_dot() -> None:
    script = _ps_apply_record(_del("mail.example.com.", "MX"))
    assert "RecordData.MailExchange" in script
    assert ".TrimEnd('.')" in script
    assert "-eq 'mail.example.com'" in script


def test_singular_txt_is_escaped_joined_and_case_sensitive() -> None:
    script = _ps_apply_record(_del('"a\'b"', "TXT"))
    # Joined the way the pull reads it, compared with -ceq (TXT is not a
    # name), and the single quote doubled inside the PS literal.
    assert "(@($_.RecordData.DescriptiveText) -join '') -ceq 'a''b'" in script


def test_singular_cname_still_deletes_the_whole_name() -> None:
    assert "Where-Object" not in _ps_apply_record(_del("t.example.com.", "CNAME"))


def test_resolved_rrset_delete_is_unchanged() -> None:
    rr = RRsetData(ttl=60, members=())
    assert "Where-Object" not in _ps_apply_record(_del("10.0.0.2", rrset=rr))


def test_batch_delete_carries_the_value_and_filters() -> None:
    script = _ps_apply_record_batch([_del("10.0.0.2"), _del("10.0.0.3")])
    ops = _batch_payload(script)
    assert [o["dv"] for o in ops] == ["10.0.0.2", "10.0.0.3"]
    assert all(o["rm"] == 1 and o["m"] == [] for o in ops)
    assert "$_.dv" in script and "$rd=$_.RecordData" in script
    # Every value-matchable type has a branch; anything else keeps the record.
    for t in ("'A'{", "'AAAA'{", "'NS'{", "'PTR'{", "'MX'{", "'TXT'{", "default{$false}"):
        assert t in script


def test_batch_without_value_delete_keeps_old_wrapper() -> None:
    members = RRsetData(ttl=60, members=(RRsetMember(value="10.0.0.9"),))
    script = _ps_apply_record_batch([_del("10.0.0.9", rrset=members)])
    assert "dv" not in _batch_payload(script)[0]
    assert "$rd=$_.RecordData" not in script


def test_batch_cname_delete_has_no_value() -> None:
    ops = _batch_payload(_ps_apply_record_batch([_del("t.example.com.", "CNAME")]))
    assert "dv" not in ops[0]


def test_value_delete_batches_fit_the_encoded_command_budget() -> None:
    eligible = [(i, _del(f"10.0.{i // 250}.{i % 250 + 1}")) for i in range(60)]
    chunks = _pack_record_chunks(eligible)
    assert len(chunks) > 1
    for chunk in chunks:
        assert encoded_command_len(_ps_apply_record_batch([c for _, c in chunk])) <= (
            MAX_ENCODED_COMMAND
        )


# ── Path A: RFC 2136 (no WinRM credentials) ──────────────────────────


async def _rfc2136_update(monkeypatch, change: RecordChange) -> Any:
    import dns.query

    from app.drivers.dns import windows

    sent: list[Any] = []
    monkeypatch.setattr(windows, "resolve_server_address", lambda *a, **k: ["192.0.2.53"])
    monkeypatch.setattr(dns.query, "tcp", lambda msg, *a, **k: sent.append(msg))
    server = SimpleNamespace(id="s1", host="dc1.example.com", api_port=53)
    await windows.WindowsDNSDriver().apply_record_change(server, change)
    (msg,) = sent
    (rrset,) = msg.update
    return rrset


async def test_rfc2136_value_delete_removes_only_that_rr(monkeypatch) -> None:
    import dns.rdataclass

    rrset = await _rfc2136_update(monkeypatch, _del("10.0.0.2"))
    # class NONE + the rdata = "delete this RR" (RFC 2136 §2.5.4); class ANY
    # with no rdata would be "delete the whole RRset" (§2.5.2).
    assert rrset.deleting == dns.rdataclass.NONE
    assert [r.to_text() for r in rrset] == ["10.0.0.2"]


async def test_rfc2136_cname_delete_still_clears_the_name(monkeypatch) -> None:
    import dns.rdataclass

    rrset = await _rfc2136_update(monkeypatch, _del("t.example.com.", "CNAME"))
    assert rrset.deleting == dns.rdataclass.ANY
    assert len(rrset) == 0
