"""#2924 — the domain options in DNS form on the paths beside write + render.

The importer preview must show what commit will store, and the Windows
cutover parity check must not report a scope as diverged only because the
importer stored ``domain-name`` in DNS form while Windows reports it as typed.
"""

from __future__ import annotations

import uuid

from app.api.v1.dhcp_import.router import _preview_to_pydantic
from app.models.dhcp import DHCPScope
from app.services.cutover.canonical import ParityReport
from app.services.cutover.parity import _diff_dhcp_options
from app.services.dhcp_import import parse_kea_config

_KEA_CONF = """
{
  "Dhcp4": {
    "subnet4": [
      {
        "subnet": "192.0.2.0/24",
        "option-data": [
          { "name": "domain-name", "data": "Cafe-é.Example.Test." },
          { "name": "domain-search", "data": "XP.Test., B.test" }
        ],
        "reservations": [
          {
            "hw-address": "aa:bb:cc:dd:ee:ff",
            "ip-address": "192.0.2.5",
            "option-data": [ { "name": "domain-name", "data": "Host.Test." } ]
          }
        ]
      }
    ],
    "client-classes": [
      {
        "name": "voip",
        "test": "substring(option[60].hex,0,6) == 'Aastra'",
        "option-data": [ { "name": "domain-name", "data": "Voip.Test." } ]
      }
    ]
  }
}
""".encode()


def test_import_preview_shows_the_dns_form_commit_stores() -> None:
    preview = parse_kea_config(_KEA_CONF)
    out = _preview_to_pydantic(preview)
    (scope,) = out.scopes
    assert scope.options["domain-name"] == "xn--cafe--fsa.example.test"
    assert scope.options["domain-search"] in ("xp.test, b.test", ["xp.test", "b.test"])
    (res,) = scope.reservations
    assert res.options["domain-name"] == "host.test"
    (cc,) = out.client_classes
    assert cc.options["domain-name"] == "voip.test"


def _report() -> ParityReport:
    return ParityReport(kind="dhcp_scope", source_ref="192.0.2.0/24")


def _scope(options: dict) -> DHCPScope:
    return DHCPScope(id=uuid.uuid4(), name="s", options=options)


def test_parity_treats_case_and_root_dot_as_the_same_domain() -> None:
    report = _report()
    _diff_dhcp_options(
        report,
        source={"options": {"domain-name": "Corp.Example.COM.", "domain-search": ["A.Test"]}},
        scope=_scope({"domain-name": "corp.example.com", "domain-search": ["a.test"]}),
        windows_only_class="never_imported",
    )
    assert report.differences == []
    assert report.in_sync == 2


def test_parity_still_reports_a_different_domain() -> None:
    """Negative control: a real difference is not hidden by the folding."""
    report = _report()
    _diff_dhcp_options(
        report,
        source={"options": {"domain-name": "Corp.Example.COM."}},
        scope=_scope({"domain-name": "other.example.com"}),
        windows_only_class="never_imported",
    )
    (diff,) = report.differences
    assert diff.classification == "value_mismatch"
    # each side is shown as it has it
    assert diff.source_value == "Corp.Example.COM."
    assert diff.target_value == "other.example.com"
