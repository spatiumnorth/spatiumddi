"""Zone-template wizard helpers.

Loads the static catalog at ``app/data/dns_zone_templates.json`` once per
process and materialises a chosen template into a list of record-create
payloads with operator-supplied parameters substituted in.

Templates can mark records ``skip_if_empty: ["param"]`` so optional fields
(DKIM selector, AD site name, IPv6 origin) drop out cleanly when not
filled in. ``skip_if_set: ["param"]`` is the inverse: a fallback record
that is written only while the parameter is blank (the Email template's
``p=none`` DMARC stub stands in for the ``rua=`` one, #3267). Every key
either list names must be one of the template's parameters.
``{{__zone__}}`` is a built-in token that resolves to the new zone's name
so apex aliases like ``www CNAME @`` can render as ``www CNAME example.com.``
without extra parameters.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

_CATALOG_PATH = Path(__file__).resolve().parents[2] / "data" / "dns_zone_templates.json"
_PLACEHOLDER_RE = re.compile(r"\{\{(\w+)\}\}")


@dataclass
class TemplateParameter:
    key: str
    label: str
    type: str
    required: bool
    default: str | None
    placeholder: str | None
    hint: str | None


@dataclass
class TemplateRecord:
    name: str
    record_type: str
    value: str
    ttl: int | None
    priority: int | None
    weight: int | None
    port: int | None
    skip_if_empty: list[str]
    skip_if_set: list[str] = field(default_factory=list)


@dataclass
class ZoneTemplate:
    id: str
    name: str
    category: str
    description: str
    parameters: list[TemplateParameter]
    records: list[TemplateRecord]

    @property
    def max_record_count(self) -> int:
        """Records written with every parameter filled in — the catalog's
        ``record_count``. A ``skip_if_set`` record is a fallback for one that
        the filled-in parameter writes instead, so counting it would promise
        a record no zone gets (#3267)."""
        return sum(1 for r in self.records if not r.skip_if_set)


@lru_cache(maxsize=1)
def load_catalog() -> dict[str, Any]:
    """Read + parse the JSON catalog. Cached for the lifetime of the process."""
    raw = json.loads(_CATALOG_PATH.read_text(encoding="utf-8"))
    return raw


def list_templates() -> list[ZoneTemplate]:
    """Return every template in the catalog as structured rows."""
    raw = load_catalog()
    templates: list[ZoneTemplate] = []
    for t in raw["templates"]:
        templates.append(
            ZoneTemplate(
                id=t["id"],
                name=t["name"],
                category=t["category"],
                description=t["description"],
                parameters=[
                    TemplateParameter(
                        key=p["key"],
                        label=p["label"],
                        type=p.get("type", "string"),
                        required=p.get("required", False),
                        default=p.get("default"),
                        placeholder=p.get("placeholder"),
                        hint=p.get("hint"),
                    )
                    for p in t.get("parameters", [])
                ],
                records=[
                    TemplateRecord(
                        name=r["name"],
                        record_type=r["record_type"],
                        value=r["value"],
                        ttl=r.get("ttl"),
                        priority=r.get("priority"),
                        weight=r.get("weight"),
                        port=r.get("port"),
                        skip_if_empty=list(r.get("skip_if_empty", [])),
                        skip_if_set=list(r.get("skip_if_set", [])),
                    )
                    for r in t.get("records", [])
                ],
            )
        )
    return templates


def get_template(template_id: str) -> ZoneTemplate | None:
    for t in list_templates():
        if t.id == template_id:
            return t
    return None


def _substitute(text: str, params: dict[str, str]) -> str:
    def repl(m: re.Match[str]) -> str:
        return params.get(m.group(1), "")

    return _PLACEHOLDER_RE.sub(repl, text)


def materialize(
    template: ZoneTemplate, zone_name: str, params: dict[str, str]
) -> list[dict[str, Any]]:
    """Resolve ``template.records`` to concrete record-create payloads.

    Empty / missing parameters skip records that list them in
    ``skip_if_empty``, and filled-in ones skip records that list them in
    ``skip_if_set``; all other placeholders that match nothing collapse
    to "" (so a careless template authoring won't 500). The reserved
    ``__zone__`` token always resolves to the zone's name with the
    trailing dot preserved — useful for apex CNAME aliasing.
    """
    full_params = {k: (v or "").strip() for k, v in params.items()}
    full_params["__zone__"] = zone_name

    out: list[dict[str, Any]] = []
    for r in template.records:
        if any(not full_params.get(k) for k in r.skip_if_empty):
            continue
        # ``skip_if_set`` is the inverse: a fallback record that stands in
        # only while the optional parameter is blank (#3267).
        if any(full_params.get(k) for k in r.skip_if_set):
            continue
        # Whitespace cleanup: SPF "v=spf1 mx  -all" → "v=spf1 mx -all"
        # when the optional includes string is empty.
        value = re.sub(r"\s+", " ", _substitute(r.value, full_params)).strip()
        name = _substitute(r.name, full_params).strip()
        if not name:
            name = "@"
        out.append(
            {
                "name": name,
                "record_type": r.record_type,
                "value": value,
                "ttl": r.ttl,
                "priority": r.priority,
                "weight": r.weight,
                "port": r.port,
            }
        )
    return out


def validate_params(template: ZoneTemplate, params: dict[str, str]) -> list[str]:
    """Return a list of operator-friendly error messages, or [] when valid."""
    errors: list[str] = []
    for p in template.parameters:
        if p.required and not (params.get(p.key) or "").strip():
            errors.append(f"{p.label} is required")
    return errors
