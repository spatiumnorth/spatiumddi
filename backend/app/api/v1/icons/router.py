"""Built-in icon catalog + default-icon mappings (#5022).

* ``GET /icons/catalog`` -- the built-in set's names, paged and searchable, so
  API clients can validate a name and the mobile app can build its own picker.
* ``GET|PUT|DELETE /icons/defaults`` -- the device-class / IP-role / network
  device type -> icon mapping. The shipped mapping lives in code; a row exists
  only for an entry an operator changed or added.

Reading needs only a signed-in user (every viewer has to be able to see icons);
changing a mapping needs ``write`` / ``delete`` on ``icon`` (superadmin by
default). Every mutation is audited with the old and new value.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from app.api.deps import DB, CurrentUser
from app.api.pagination import DEFAULT_PAGE_SIZE, MAX_PAGE, MAX_PAGE_SIZE, Page
from app.core.permissions import require_resource_permission
from app.models.audit import AuditLog
from app.models.icon import IconDefault
from app.services import icons as icon_svc

router = APIRouter()

IconKind = Literal["device_class", "ip_role"]


class IconCatalogItem(BaseModel):
    name: str
    label: str


class IconDefaultItem(BaseModel):
    kind: IconKind
    match_value: str
    icon: str
    # The shipped icon for this key, null for an operator-added mapping.
    default_icon: str | None
    overridden: bool


class IconDefaultList(BaseModel):
    items: list[IconDefaultItem]


class IconDefaultPut(BaseModel):
    kind: IconKind
    match_value: str = Field(min_length=1, max_length=100)
    icon: str

    @field_validator("icon", mode="before")
    @classmethod
    def _icon(cls, v: object) -> object:
        out = icon_svc.validate_icon(v)
        if out is None:
            raise ValueError("icon is required")
        return out

    @field_validator("match_value")
    @classmethod
    def _match(cls, v: str) -> str:
        norm = icon_svc.normalise_match(v)
        if not norm:
            raise ValueError("match_value must not be blank")
        return norm


def _item(kind: str, match: str) -> IconDefaultItem:
    for row in icon_svc.default_mapping_rows():
        if row["kind"] == kind and row["match_value"] == match:
            return IconDefaultItem(**row)
    raise HTTPException(status_code=404, detail="No such icon mapping")


@router.get("/catalog", response_model=Page[IconCatalogItem])
async def icon_catalog(
    _: CurrentUser,
    q: str | None = Query(None, description="search names, aliases and tags"),
    page: int = Query(1, ge=1, le=MAX_PAGE),
    page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
) -> Page[IconCatalogItem]:
    hits = icon_svc.search_catalog(q)
    start = (page - 1) * page_size
    return Page[IconCatalogItem](
        items=[
            IconCatalogItem(name=e.name, label=e.label) for e in hits[start : start + page_size]
        ],
        total=len(hits),
        page=page,
        page_size=page_size,
    )


@router.get("/defaults", response_model=IconDefaultList)
async def list_icon_defaults(_: CurrentUser, db: DB) -> IconDefaultList:
    await icon_svc.refresh_overrides(db, force=True)
    return IconDefaultList(items=[IconDefaultItem(**r) for r in icon_svc.default_mapping_rows()])


@router.put(
    "/defaults",
    response_model=IconDefaultItem,
    dependencies=[Depends(require_resource_permission("icon"))],
)
async def put_icon_default(
    body: IconDefaultPut, current_user: CurrentUser, db: DB
) -> IconDefaultItem:
    row = (
        await db.execute(
            select(IconDefault).where(
                IconDefault.kind == body.kind, IconDefault.match_value == body.match_value
            )
        )
    ).scalar_one_or_none()
    shipped = icon_svc.SHIPPED_DEFAULTS[body.kind].get(body.match_value)
    old = row.icon if row is not None else shipped
    if row is None:
        # Setting an entry to what ships is not a change; a row would only
        # freeze the entry against later shipped-mapping updates.
        if body.icon != shipped:
            db.add(IconDefault(kind=body.kind, match_value=body.match_value, icon=body.icon))
    elif body.icon == shipped:
        await db.delete(row)
    else:
        row.icon = body.icon
    if old != body.icon:
        db.add(
            AuditLog(
                user_id=current_user.id,
                user_display_name=current_user.display_name,
                auth_source=current_user.auth_source,
                action="update",
                resource_type="icon_default",
                resource_id=f"{body.kind}:{body.match_value}",
                resource_display=f"{body.kind} {body.match_value}",
                old_value={"icon": old},
                new_value={"icon": body.icon},
                result="success",
            )
        )
    await db.commit()
    await icon_svc.refresh_overrides(db, force=True)
    return _item(body.kind, body.match_value)


@router.delete(
    "/defaults",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_resource_permission("icon"))],
)
async def delete_icon_default(
    current_user: CurrentUser,
    db: DB,
    kind: IconKind = Query(...),
    match_value: str = Query(..., min_length=1, max_length=100),
) -> None:
    """Revert an entry to the shipped icon, or remove one an operator added."""
    match = icon_svc.normalise_match(match_value)
    row = (
        await db.execute(
            select(IconDefault).where(IconDefault.kind == kind, IconDefault.match_value == match)
        )
    ).scalar_one_or_none()
    if row is None:
        # A shipped entry nobody changed has nothing to delete; a key that is
        # neither shipped nor operator-added does not exist.
        if match in icon_svc.SHIPPED_DEFAULTS[kind]:
            raise HTTPException(
                status_code=409, detail="This mapping is the shipped default; nothing to reset"
            )
        raise HTTPException(status_code=404, detail="No such icon mapping")
    old = row.icon
    await db.delete(row)
    db.add(
        AuditLog(
            user_id=current_user.id,
            user_display_name=current_user.display_name,
            auth_source=current_user.auth_source,
            action="delete",
            resource_type="icon_default",
            resource_id=f"{kind}:{match}",
            resource_display=f"{kind} {match}",
            old_value={"icon": old},
            new_value={"icon": icon_svc.SHIPPED_DEFAULTS[kind].get(match)},
            result="success",
        )
    )
    await db.commit()
    await icon_svc.refresh_overrides(db, force=True)
