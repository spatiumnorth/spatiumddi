"""Vendor key -> provider class for the commercial-DDI mirror (#4729)."""

from __future__ import annotations

from app.services.ddi_mirror.base import DDIProvider
from app.services.ddi_mirror.infoblox import InfobloxProvider

PROVIDERS: dict[str, type[DDIProvider]] = {
    InfobloxProvider.vendor: InfobloxProvider,
}

# Named in the issue, not built yet — the API answers these with a clear 422
# instead of a bare "unknown vendor".
PLANNED_VENDORS: tuple[str, ...] = ("bluecat", "efficientip")


def vendor_error(vendor: str) -> str | None:
    """The 422 text for a vendor that cannot be used, or None when it can."""
    if vendor in PROVIDERS:
        return None
    if vendor in PLANNED_VENDORS:
        return f"vendor {vendor!r} is planned but not supported yet"
    return f"unknown vendor {vendor!r}; supported: {', '.join(sorted(PROVIDERS))}"


def get_provider_class(vendor: str) -> type[DDIProvider]:
    cls = PROVIDERS.get(vendor)
    if cls is None:
        raise ValueError(vendor_error(vendor))
    return cls


__all__ = ["PLANNED_VENDORS", "PROVIDERS", "get_provider_class", "vendor_error"]
