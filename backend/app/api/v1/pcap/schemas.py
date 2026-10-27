"""Pydantic schemas for the packet-capture API (issue #59)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.services.pcap.runner import (
    HARD_MAX_BYTES,
    HARD_MAX_DURATION_S,
    HARD_MAX_PACKETS,
    MAX_SNAPLEN,
)

PcapVantageKind = Literal["server", "appliance"]
PcapStatus = Literal["queued", "running", "completed", "failed", "cancelled"]


class PcapCaptureCreate(BaseModel):
    """Operator request to start a capture.

    At least one stop condition (``max_packets`` / ``max_duration_s`` /
    ``max_bytes``) is required — enforced server-side in the runner's
    ``clamp_caps``. ``bpf_filter`` is passed to tcpdump as a single
    trailing argv element (never shell-interpolated)."""

    vantage_kind: PcapVantageKind = "server"
    appliance_id: uuid.UUID | None = None
    interface: str | None = None
    bpf_filter: str | None = Field(default=None, max_length=1024)
    snaplen: int = Field(default=256, ge=0, le=MAX_SNAPLEN)
    promiscuous: bool = False
    max_packets: int | None = Field(default=10_000, ge=1, le=HARD_MAX_PACKETS)
    max_duration_s: int | None = Field(default=60, ge=1, le=HARD_MAX_DURATION_S)
    max_bytes: int | None = Field(default=50 * 1024 * 1024, ge=1, le=HARD_MAX_BYTES)


class PcapCaptureRead(BaseModel):
    id: uuid.UUID
    vantage_kind: str
    appliance_id: uuid.UUID | None
    vantage_label: str
    interface: str | None
    bpf_filter: str | None
    snaplen: int
    promiscuous: bool
    max_packets: int | None
    max_duration_s: int | None
    max_bytes: int | None
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    duration_seconds: float | None
    exit_code: int | None
    command_line: str | None
    error_message: str | None
    packets_captured: int
    bytes_captured: int
    pcap_size_bytes: int | None
    pcap_sha256: str | None
    # Node whose disk holds the artifact (#2866); null when unknown.
    artifact_node: str | None = None
    # True when the row has captured bytes available to download.
    has_artifact: bool = False
    metadata_json: dict | None = None
    created_by_user_id: uuid.UUID | None
    created_at: datetime
    modified_at: datetime


class PcapCaptureListResponse(BaseModel):
    items: list[PcapCaptureRead]
    total: int
    page: int
    page_size: int


class PcapInterfacesResponse(BaseModel):
    interfaces: list[str]
    # Honest UI label about what this vantage can actually see.
    note: str


class PcapBulkDeleteRequest(BaseModel):
    capture_ids: list[uuid.UUID] = Field(min_length=1, max_length=500)


__all__ = [
    "PcapVantageKind",
    "PcapStatus",
    "PcapCaptureCreate",
    "PcapCaptureRead",
    "PcapCaptureListResponse",
    "PcapInterfacesResponse",
    "PcapBulkDeleteRequest",
]
