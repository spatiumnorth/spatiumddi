"""Typed ``Response`` subclasses so a non-JSON route documents itself (#921).

FastAPI derives a route's documented success media type from its
``response_class``, and the default is ``JSONResponse``. A handler annotated
``-> Response`` that streams a zip therefore publishes ``application/json``,
which a generated client cannot decode and a strict validator rejects.

Adding ``responses={200: {"content": {"application/zip": {}}}}`` — the shape
#861 used for the ``export.pdf`` routes — **merges** with that default rather
than replacing it, so the route ends up declaring BOTH. That silences the
conformance failure (the served type is now documented) while still telling a
generator the endpoint might return JSON, which it never does.

Setting ``response_class`` is what replaces it. It has to be a subclass that
declares ``media_type``: the bare ``Response`` and ``StreamingResponse``
classes leave it ``None``, and FastAPI then documents *no* content at all —
worse than the JSON it was meant to correct.

These change documentation only. Every handler using them returns an explicit
``Response`` it built itself, so ``response_class`` never touches the wire.
Keep the class's ``media_type`` and the handler's ``media_type=`` the same —
``tests/test_response_media_types.py`` compares exactly those two.
"""

from __future__ import annotations

from fastapi import Response


class ZipResponse(Response):
    media_type = "application/zip"


class PdfResponse(Response):
    media_type = "application/pdf"


class OctetStreamResponse(Response):
    media_type = "application/octet-stream"


class XmlResponse(Response):
    media_type = "application/xml"


class HeldXmlResponse(Response):
    """HELD (RFC 5985 §6.5) requires ``application/held+xml``, not
    ``application/xml`` — a client content-negotiating on it would not
    recognise the generic type."""

    media_type = "application/held+xml"


class PlainTextStreamResponse(Response):
    """``text/plain`` for a body assembled and returned whole (pod logs)."""

    media_type = "text/plain"


class EventStreamResponse(Response):
    """Server-sent events. The handler still returns a ``StreamingResponse``;
    this exists only so the documented type isn't ``application/json``."""

    media_type = "text/event-stream"


class CsvResponse(Response):
    media_type = "text/csv"


class JsonLinesResponse(Response):
    """One JSON object per line (``application/x-ndjson``), for streamed exports."""

    media_type = "application/x-ndjson"


class IosConfigResponse(Response):
    """Generated switch-configuration text for an operator to review.
    ``text/plain`` rather than a made-up type, so a browser shows it."""

    media_type = "text/plain"


class DnsZoneResponse(Response):
    """A zone in RFC 1035 master-file format."""

    media_type = "text/dns"


class PcapResponse(Response):
    media_type = "application/vnd.tcpdump.pcap"


__all__ = [
    "DnsZoneResponse",
    "EventStreamResponse",
    "OctetStreamResponse",
    "PcapResponse",
    "PdfResponse",
    "PlainTextStreamResponse",
    "XmlResponse",
    "ZipResponse",
]
