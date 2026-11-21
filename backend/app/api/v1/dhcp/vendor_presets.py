"""DHCP option 43 vendor presets (issue #4490).

Read-only: lists the bundled presets and encodes controller addresses into
the option 43 hex for one of them. Nothing is stored; the UI drops the
result into an option row (and, for presets that name one, the option-60
fence of a phone profile).
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.core.permissions import require_resource_permission
from app.services.dhcp.vendor_presets import encode_preset, get_preset, list_presets

router = APIRouter(
    tags=["dhcp"],
    dependencies=[Depends(require_resource_permission("dhcp_scope"))],
)


class VendorPresetDef(BaseModel):
    id: str
    vendor: str
    product: str
    description: str
    option_code: int
    min_controllers: int
    max_controllers: int
    controller_label: str
    vendor_class_match: str | None
    vendor_class_note: str
    source: str


class VendorPresetEncoded(BaseModel):
    preset_id: str
    option_code: int
    value: str
    byte_length: int
    vendor_class_match: str | None


@router.get("/vendor-presets", response_model=list[VendorPresetDef])
async def list_vendor_presets() -> list[VendorPresetDef]:
    """Every bundled option 43 vendor preset, ordered by vendor."""
    return [
        VendorPresetDef(
            id=p.id,
            vendor=p.vendor,
            product=p.product,
            description=p.description,
            option_code=p.option_code,
            min_controllers=p.min_controllers,
            max_controllers=p.max_controllers,
            controller_label=p.controller_label,
            vendor_class_match=p.vendor_class_match,
            vendor_class_note=p.vendor_class_note,
            source=p.source,
        )
        for p in list_presets()
    ]


@router.get("/vendor-presets/{preset_id}/encode", response_model=VendorPresetEncoded)
async def encode_vendor_preset(
    preset_id: str,
    controller: Annotated[list[str], Query(max_length=64)] = [],  # noqa: B006
) -> VendorPresetEncoded:
    """Encode ``controller`` addresses (repeat the parameter) into the preset's
    option 43 value, as plain hex ready for an option row."""
    preset = get_preset(preset_id)
    if preset is None:
        raise HTTPException(status_code=404, detail="Unknown vendor preset")
    try:
        enc = encode_preset(preset, controller)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return VendorPresetEncoded(
        preset_id=preset.id,
        option_code=preset.option_code,
        value=enc.value_hex,
        byte_length=enc.byte_length,
        vendor_class_match=preset.vendor_class_match,
    )
