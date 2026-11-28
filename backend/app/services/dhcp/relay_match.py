"""Structured relay-agent (option 82) match for a client class (#54).

The operator picks a sub-option, an operator and a value; this module checks
it, normalises it, and hands the driver a backend-neutral ``RelayMatchSpec``
holding BYTES. The driver compiles those bytes to its own test syntax
(``KeaDriver.compile_relay_match``), so no operator-typed character is ever
part of an expression: a ``text`` value becomes UTF-8 bytes and then hex, and
a ``hex`` value is validated to ``[0-9A-F]`` before it is used.

Stored normalised: ``hex`` values uppercase with no separators or ``0x``,
``text`` values as typed. Re-submitting a stored spec is therefore a no-op,
which a round trip through the UI relies on.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

from app.drivers.dhcp.base import RelayMatchCondition, RelayMatchSpec

MAX_CONDITIONS = 16
MAX_VALUE_BYTES = 255  # a sub-option's length octet
MAX_OFFSET = 254

RelayOp = Literal[
    "exists", "not_exists", "equals", "not_equals", "starts_with", "ends_with", "slice"
]
_EXISTENCE_OPS = ("exists", "not_exists")

# Names for the sub-options an operator is likely to pick (RFC 3046 / 3527 /
# 4580 / 5107). Any 1-255 is accepted; these only label the compiled preview.
SUB_OPTION_NAMES: dict[int, str] = {
    1: "circuit-id",
    2: "remote-id",
    6: "subscriber-id",
    12: "relay-id",
}

_HEX_SEPARATORS = re.compile(r"[:\-. \t]")
_HEX_ONLY = re.compile(r"[0-9A-Fa-f]+")


class RelayMatchConditionModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sub_option: Annotated[StrictInt, Field(ge=1, le=255)]
    op: RelayOp
    encoding: Literal["text", "hex"] = "text"
    value: str | None = None
    offset: Annotated[StrictInt, Field(ge=0, le=MAX_OFFSET)] | None = None

    @model_validator(mode="after")
    def _check(self) -> RelayMatchConditionModel:
        if self.op in _EXISTENCE_OPS:
            if self.value is not None:
                raise ValueError(f"'{self.op}' takes no value")
            if self.offset is not None:
                raise ValueError(f"'{self.op}' takes no offset")
            return self
        if self.value is None:
            raise ValueError(f"'{self.op}' needs a value")
        if self.op == "slice":
            if self.offset is None:
                raise ValueError("'slice' needs an offset")
        elif self.offset is not None:
            raise ValueError("offset is only valid with 'slice'")
        # Decode now so every refusal is raised at validation, and store hex normalised.
        raw = decode_value(self.encoding, self.value)
        if self.encoding == "hex":
            self.value = raw.hex().upper()
        return self

    def value_bytes(self) -> bytes | None:
        return None if self.value is None else decode_value(self.encoding, self.value)


class RelayMatchSpecModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["relay_agent"] = "relay_agent"
    combine: Literal["all", "any"] = "all"
    conditions: Annotated[
        list[RelayMatchConditionModel], Field(min_length=1, max_length=MAX_CONDITIONS)
    ]

    def to_def(self) -> RelayMatchSpec:
        return RelayMatchSpec(
            combine=self.combine,
            conditions=tuple(
                RelayMatchCondition(
                    sub_option=c.sub_option, op=c.op, value=c.value_bytes(), offset=c.offset
                )
                for c in self.conditions
            ),
        )

    def stored(self) -> dict[str, Any]:
        """The JSON kept in ``dhcp_client_class.match_spec``."""
        return self.model_dump(mode="json", exclude_none=True)


def decode_value(encoding: str, value: str) -> bytes:
    """``value`` as bytes, or ``ValueError`` saying what is wrong with it."""
    if encoding == "hex":
        h = value.strip()
        if h[:2] in ("0x", "0X"):
            h = h[2:]
        h = _HEX_SEPARATORS.sub("", h)
        if not h:
            raise ValueError("value is empty")
        if not _HEX_ONLY.fullmatch(h):
            raise ValueError("hex value may only contain 0-9, A-F and the separators : - . space")
        if len(h) % 2:
            raise ValueError("hex value has an odd number of digits")
        raw = bytes.fromhex(h)
    else:
        if "�" in value:
            # A value pasted from a lossy decode can never match what the relay sent.
            raise ValueError(
                "value contains U+FFFD (a replacement character); enter the bytes as hex instead"
            )
        if "\x00" in value:
            # Postgres JSONB cannot store U+0000, and the spec is kept as JSONB.
            raise ValueError("text value contains a NUL character; enter the bytes as hex instead")
        try:
            raw = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("value is not valid text (lone surrogate); use hex") from exc
        if not raw:
            raise ValueError("value is empty")
    if len(raw) > MAX_VALUE_BYTES:
        raise ValueError(f"value is {len(raw)} bytes; a sub-option holds at most {MAX_VALUE_BYTES}")
    return raw


def parse_spec(raw: Any) -> RelayMatchSpecModel:
    """Validate ``raw`` (a dict from the API or the stored column)."""
    return RelayMatchSpecModel.model_validate(raw)


def spec_warnings(spec: RelayMatchSpecModel) -> list[str]:
    """Non-blocking notes shown next to the compiled test."""
    out: list[str] = []
    if all(c.op == "not_exists" for c in spec.conditions):
        out.append(
            "Every condition is 'not exists': this matches clients that carry no such "
            "sub-option, which includes every client that is not behind a relay."
        )
    elif all(c.op in ("not_equals", "not_exists") for c in spec.conditions):
        out.append(
            "'not equals' needs the sub-option to be present, so a client with no option 82 "
            "does not match it. Add a 'not exists' condition under 'any' to include those."
        )
    for c in spec.conditions:
        if c.encoding == "text" and c.value is not None and not _printable_ascii(c.value):
            out.append(
                f"Sub-option {c.sub_option}: the text value is not printable ASCII; "
                "it is matched as its UTF-8 bytes."
            )
    return out


def _printable_ascii(value: str) -> bool:
    return all(0x20 <= ord(ch) < 0x7F for ch in value)
