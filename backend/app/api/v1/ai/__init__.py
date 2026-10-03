"""Operator Copilot API surface (issue #90).

Re-exports a single ``router`` that combines:
    /api/v1/ai/providers/...  — provider config CRUD (Wave 1)
    /api/v1/ai/tools          — tool catalog introspection (Wave 2)
    /api/v1/ai/mcp            — MCP JSON-RPC endpoint (Wave 2)
    /api/v1/ai/available      — is a chat possible? any signed-in user (#1345)
    /api/v1/ai/sessions       — chat session CRUD (Wave 3)
    /api/v1/ai/chat           — chat streaming endpoint (Wave 3)
    /api/v1/ai/usage          — usage stats (per-user + admin) (Wave 4)
    /api/v1/ai/prompts        — reusable prompt library (Phase 2)
    /api/v1/ai/proposals      — write-operation proposals (Phase 2)
"""

from fastapi import APIRouter

from app.api.v1.ai.chat import router as chat_router
from app.api.v1.ai.mcp import router as mcp_router
from app.api.v1.ai.prompts import router as prompts_router
from app.api.v1.ai.proposals import router as proposals_router
from app.api.v1.ai.providers import router as providers_router
from app.api.v1.ai.tools import router as tools_router
from app.api.v1.ai.usage import router as usage_router

router = APIRouter()
router.include_router(providers_router)
router.include_router(tools_router)
router.include_router(mcp_router, prefix="/mcp")
router.include_router(chat_router)
router.include_router(usage_router)
router.include_router(prompts_router)
router.include_router(proposals_router)

__all__ = ["router"]
