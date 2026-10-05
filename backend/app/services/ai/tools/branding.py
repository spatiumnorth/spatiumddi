"""Operator Copilot read tool for the branding surface (issues #885-#888).

Surfaces the singleton ``platform_settings`` branding slice plus whether a
custom logo is stored, so an operator can ask "is the login banner on?",
"what does the login notice say?", "which environment is this box labelled
as?", or "are we using a custom logo?".

Read-only, and there is deliberately no ``propose_update_branding``: every
field here renders to *anonymous* visitors on the login page, which is why
the REST write path is superadmin-only rather than the ``write:settings``
the rest of the settings PUT takes. That is not a gate to hand to a chat
tool — the friendly path is Settings -> Branding, which also carries the
colour-contrast warning and the live preview.

``module=None`` (always available) — branding is not behind a feature
module; the write half is gated at the handler level (superadmin), like the
other host-config settings tools.

``default_enabled=True`` (NN #13) — read-only, and nothing it returns is a
secret: the identical payload is served unauthenticated from
``GET /api/v1/settings/public``.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.settings import (
    BRANDING_ASSET_KIND_LOGO,
    BrandingAsset,
    PlatformSettings,
)
from app.services.ai.tools.base import register_tool


class FindBrandingSettingsArgs(BaseModel):
    """No arguments — there is exactly one branding config row."""

    pass


@register_tool(
    name="find_branding_settings",
    permission="authenticated",
    description=(
        "Return the platform branding configuration — the product title "
        "shown in the browser tab / sign-in heading / sidebar wordmark, "
        "the login acceptable-use banner (enabled, heading, text, and "
        "whether an acknowledgement checkbox gates sign-in), the "
        "environment banner (enabled, text, hex colours, and whether it "
        "renders top / bottom / both), and whether a custom logo is "
        "uploaded. Use to answer 'is the login banner on?', 'what does "
        "our login notice say?', 'which environment is this labelled as?' "
        "or 'are we using a custom logo?'. Everything here is also served "
        "unauthenticated to the login page, so none of it is secret."
    ),
    args_model=FindBrandingSettingsArgs,
    category="admin",
    default_enabled=True,
)
async def find_branding_settings(
    db: AsyncSession, user: User, args: FindBrandingSettingsArgs
) -> dict[str, Any]:
    # Same transient-instance stand-in the public endpoint uses: on a fresh
    # install the settings row does not exist until the first write, and the
    # answer should be the defaults rather than an error. Its columns read as
    # None (ORM ``default=`` applies at flush, not construction), so the
    # ``or`` fallbacks below supply the actual defaults.
    settings = await db.get(PlatformSettings, 1) or PlatformSettings()
    logo = (
        await db.execute(
            select(BrandingAsset.sha256, BrandingAsset.byte_size).where(
                BrandingAsset.kind == BRANDING_ASSET_KIND_LOGO
            )
        )
    ).one_or_none()

    return {
        "app_title": settings.app_title or "SpatiumDDI",
        "login_banner": {
            "enabled": bool(settings.login_banner_enabled),
            "title": settings.login_banner_title or "",
            "text": settings.login_banner_text or "",
            "require_ack": bool(settings.login_banner_require_ack),
        },
        "env_banner": {
            "enabled": bool(settings.env_banner_enabled),
            "text": settings.env_banner_text or "",
            "background_colour": settings.env_banner_bg or "#b91c1c",
            "text_colour": settings.env_banner_fg or "#ffffff",
            "position": settings.env_banner_position or "top",
        },
        "custom_logo": {
            "configured": logo is not None,
            "sha256": logo.sha256 if logo else None,
            "byte_size": logo.byte_size if logo else None,
        },
        "note": (
            "Branding writes are superadmin-only because these fields render "
            "to anonymous visitors on the login page. Change them in "
            "Settings -> Branding."
        ),
    }
