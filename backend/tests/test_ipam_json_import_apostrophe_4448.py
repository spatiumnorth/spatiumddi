"""#4448: JSON import keeps a leading apostrophe the JSON export never added."""

from __future__ import annotations

import json

from app.services.ipam_io.parser import parse_payload


def test_json_import_keeps_a_leading_apostrophe_4448() -> None:
    body = json.dumps(
        {
            "subnets": [{"network": "10.9.0.0/24", "name": "'-x", "'note": "'=sum"}],
            "addresses": [{"address": "10.9.0.5", "hostname": "'@h"}],
        }
    ).encode()
    parsed = parse_payload(body, "x.json", "application/json")
    assert parsed.subnets[0]["name"] == "'-x"
    assert parsed.subnets[0]["custom_fields"]["'note"] == "'=sum"
    assert parsed.addresses[0]["hostname"] == "'@h"
    # CSV still undoes the export's escape.
    csv = parse_payload(b"network,name\n10.9.0.0/24,'-x\n", "x.csv", "text/csv")
    assert csv.subnets[0]["name"] == "-x"
