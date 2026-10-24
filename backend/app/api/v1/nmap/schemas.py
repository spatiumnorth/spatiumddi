"""Pydantic schemas for the on-demand nmap API."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

NmapPreset = Literal[
    "quick",
    "service_version",
    "os_fingerprint",
    "service_and_os",
    "subnet_sweep",
    "default_scripts",
    "udp_top1000",
    "aggressive",
    "custom",
]

NmapScanStatus = Literal["queued", "running", "completed", "failed", "cancelled"]


class NmapPortResult(BaseModel):
    port: int
    proto: str
    state: str
    reason: str | None = None
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None


class NmapOsResult(BaseModel):
    name: str | None = None
    accuracy: int | None = None


class NmapHostResult(BaseModel):
    """One alive/down host from a multi-target (CIDR) scan."""

    address: str | None = None
    hostname: str | None = None
    host_state: str = "unknown"
    ports: list[NmapPortResult] = Field(default_factory=list)
    os: NmapOsResult | None = None


class NmapSummary(BaseModel):
    host_state: str = "unknown"
    ports: list[NmapPortResult] = Field(default_factory=list)
    os: NmapOsResult | None = None
    # Populated when the scan target was a CIDR (or any target nmap
    # expanded to multiple hosts). The single-host fields above mirror
    # the first entry so existing single-host callers keep working.
    hosts: list[NmapHostResult] | None = None


class NmapScanCreate(BaseModel):
    """Operator request to start a new scan.

    Either ``ip_address_id`` is supplied (the IPAM detail-modal path)
    or ``target_ip`` alone (the standalone /tools/nmap page). When
    both are present, ``target_ip`` wins — operators occasionally want
    to scan a different IP than the row they opened the modal from.
    """

    target_ip: str
    preset: NmapPreset = "quick"
    port_spec: str | None = None
    extra_args: str | None = None
    ip_address_id: uuid.UUID | None = None
    # Proceed against a scope marked do-not-probe (#722). Superadmin
    # only, audited, and per-request — nothing is remembered, so the
    # next scan of the same target is refused again.
    override_do_not_probe: bool = False

    @field_validator("port_spec", "extra_args")
    @classmethod
    def _strip_blank(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        return v or None


class NmapScanRead(BaseModel):
    id: uuid.UUID
    target_ip: str
    ip_address_id: uuid.UUID | None
    # The IP space of the IPAM row the scan was launched from (#2577) —
    # where ``stamp-discovered`` writes when no space is named. Filled on
    # the single-scan GET only.
    ip_space_id: uuid.UUID | None = None
    ip_space_name: str | None = None
    preset: str
    port_spec: str | None
    extra_args: str | None
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    duration_seconds: float | None
    exit_code: int | None
    command_line: str | None
    error_message: str | None
    summary: NmapSummary | None
    raw_xml: str | None = None
    raw_stdout: str | None = None
    created_by_user_id: uuid.UUID | None
    created_at: datetime
    modified_at: datetime

    @field_validator("target_ip", mode="before")
    @classmethod
    def _stringify(cls, v: Any) -> Any:
        return str(v) if v is not None else v


class NmapScanListResponse(BaseModel):
    items: list[NmapScanRead]
    total: int
    page: int
    page_size: int


__all__ = [
    "NmapPreset",
    "NmapScanStatus",
    "NmapPortResult",
    "NmapOsResult",
    "NmapHostResult",
    "NmapSummary",
    "NmapScanCreate",
    "NmapScanRead",
    "NmapScanListResponse",
]
