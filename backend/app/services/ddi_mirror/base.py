"""Vendor-neutral provider contract for the commercial-DDI mirror (#4729).

A provider knows how to authenticate to one product, page its objects out and
map each into a ``SourceObject``. Everything above it (reconcile, rehearsal,
API) speaks only these types, so a new vendor is one new module plus one
registry line.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

# Neutral object kinds shared by every provider (``DDIMirrorObject.kind``).
KIND_VIEW = "view"
KIND_CONTAINER = "container"
KIND_NETWORK = "network"
KIND_RANGE = "range"
KIND_RESERVATION = "reservation"
KIND_HOST = "host"
KIND_A = "a"
KIND_PTR = "ptr"
KIND_ZONE = "zone"

ALL_KINDS: tuple[str, ...] = (
    KIND_VIEW,
    KIND_CONTAINER,
    KIND_NETWORK,
    KIND_RANGE,
    KIND_RESERVATION,
    KIND_ZONE,
    KIND_HOST,
    KIND_A,
    KIND_PTR,
)


class DDIProviderError(Exception):
    """A provider call failed. ``status_code`` is the HTTP status for a response
    failure and ``None`` for a transport failure (timeout, refused, TLS)."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code

    @property
    def is_auth(self) -> bool:
        return self.status_code in (401, 403)


@dataclass
class ProviderConfig:
    """Connection settings the reconciler hands a provider."""

    base_url: str
    api_version: str
    username: str
    password: str
    verify_tls: bool = True
    ca_bundle_pem: str = ""
    network_view: str = ""
    dns_view: str = ""
    page_size: int = 500
    # Tests inject an ``httpx.MockTransport`` here; production leaves it None.
    transport: Any = None


@dataclass
class SourceObject:
    kind: str
    source_ref: str
    name: str = ""
    view: str = ""
    value: str = ""
    comment: str = ""
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProbeInfo:
    version: str
    detail: str = ""


@dataclass
class FetchResult:
    """One kind's pull. ``complete`` is False when the pull stopped early (the
    per-kind object cap): the reconciler then keeps rows it did not see rather
    than deleting what may simply be past the cap."""

    objects: list[SourceObject] = field(default_factory=list)
    unmapped: list[str] = field(default_factory=list)
    complete: bool = True


class DDIProvider(ABC):
    vendor: str = ""
    label: str = ""
    kinds: tuple[str, ...] = ALL_KINDS

    def __init__(self, config: ProviderConfig) -> None:
        self.config = config

    async def __aenter__(self) -> DDIProvider:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None

    @abstractmethod
    async def probe(self) -> ProbeInfo:
        """Authenticate and read one cheap object; raises ``DDIProviderError``."""

    @abstractmethod
    async def fetch(self, kind: str) -> FetchResult:
        """Pull every object of ``kind`` (bounded paging); raises ``DDIProviderError``."""


__all__ = [
    "ALL_KINDS",
    "DDIProvider",
    "DDIProviderError",
    "FetchResult",
    "ProbeInfo",
    "ProviderConfig",
    "SourceObject",
]
