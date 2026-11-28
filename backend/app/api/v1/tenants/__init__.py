"""Tenants -- the multi-tenancy boundary (#4263, phase 1 of #695)."""

from app.api.v1.tenants.router import router

__all__ = ["router"]
