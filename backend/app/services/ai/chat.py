"""Operator Copilot chat orchestrator (issue #90 Wave 3).

Runs the tool-call loop on the backend, hiding multi-round
tool-calling behind a single streamed response so the frontend
just sees text tokens + tool-call cards arrive in order.

Flow per inbound user message::

    1. Persist user message.
    2. Build messages = [system, …history…, user].
    3. driver.chat(messages, tools=registry.read_only()) → async iter.
    4. Buffer chunks:
        - content_delta → emit to caller, accumulate to assistant content.
        - tool_call_delta → buffer tool calls until finish_reason
          arrives; persist + dispatch each one.
        - finish_reason="tool_calls" → loop back to step 3 with the
          tool result messages appended (cap at MAX_TOOL_ROUNDS to
          prevent runaway loops).
        - finish_reason="stop"|"length" → persist final assistant
          message, emit ``done``, exit.

The orchestrator is the canonical interface for chat — both the
streaming HTTP endpoint (Wave 3) and any non-streaming test path
go through ``ChatOrchestrator``. Token / cost accounting happens
here so it's centralised for Wave 4 to extend.
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import Select, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.llm import get_driver
from app.drivers.llm.base import (
    ChatMessage,
    ChatRequest,
    ToolCall,
    ToolDefinition,
)
from app.models.ai import AIChatMessage, AIChatSession, AIProvider
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dhcp import DHCPScope, DHCPServerGroup
from app.models.dns import DNSRecord, DNSServerGroup, DNSZone
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.network import NetworkDevice
from app.models.settings import PlatformSettings
from app.services import feature_modules as fm_svc
from app.services.ai.pricing import compute_cost
from app.services.ai.tools import (
    REGISTRY,
    ToolArgumentError,
    ToolDisabled,
    ToolNotFound,
    effective_tool_names,
)

logger = structlog.get_logger(__name__)

# Cap on tool-call iterations per user turn. Five rounds is plenty
# for the read-only tool surface — most queries resolve in 1-2.
MAX_TOOL_ROUNDS: int = 5

# Hard cap on total chat history length sent to the model. Beyond
# this we drop oldest messages (preserving the system message). Stops
# token cost from running away on long sessions.
MAX_HISTORY_MESSAGES: int = 40


def _is_transient_failure(exc: BaseException) -> bool:
    """Decide whether a driver error is worth retrying on a fallback
    provider. Transient = network hiccup, server-side 5xx, rate limit.
    Configuration errors (auth, schema) are NOT retried — they need
    operator action and surface untouched.

    The match is on the SDK exception class name rather than ``isinstance``
    so we can recognise both OpenAI- and Anthropic-flavoured errors
    without import-time coupling between drivers.
    """
    name = type(exc).__name__
    transient_class_names = {
        # OpenAI + Anthropic share these names.
        "APIConnectionError",
        "APITimeoutError",
        "APIConnectionTimeoutError",
        "APIResponseValidationError",
        "InternalServerError",
        "ServiceUnavailableError",
        "RateLimitError",
        # Generic asyncio / httpx
        "TimeoutError",
        "ReadTimeout",
        "ConnectError",
        "ConnectTimeout",
    }
    if name in transient_class_names:
        return True
    # APIStatusError covers any non-2xx — only treat 5xx + 429 as transient.
    status_code = getattr(exc, "status_code", None)
    if isinstance(status_code, int) and (status_code >= 500 or status_code == 429):
        return True
    return False


# ── Streaming events ──────────────────────────────────────────────────


@dataclass(frozen=True)
class StreamEvent:
    """One event yielded by :meth:`ChatOrchestrator.stream_turn`. The
    HTTP endpoint translates these to SSE frames; tests can consume
    them directly.
    """

    kind: str  # "session" | "content" | "tool_call" | "tool_result" | "done" | "error"
    data: dict[str, Any] = field(default_factory=dict)


# ── System prompt ─────────────────────────────────────────────────────


_STATIC_SYSTEM_PROMPT = """\
# Operator Copilot — system prompt

You are **SpatiumDDI's Operator Copilot**, an in-product assistant
embedded inside SpatiumDDI's web UI. SpatiumDDI is a production-grade
open-source **DDI** (DNS, DHCP, IPAM) control plane: it owns the source
of truth for IP space, DNS zones, and DHCP scopes, and it directly
manages the backends that serve those records — agent-run BIND9 /
PowerDNS / Technitium containers, agentless Windows DNS (WinRM), and
cloud-hosted DNS (Cloudflare, Route 53, Azure DNS, Google Cloud DNS,
DigitalOcean, Hetzner, Linode, Vultr) on the DNS side; Kea agents and
Windows DHCP on the DHCP side.

The user you are talking to is an authenticated SpatiumDDI operator —
typically a network engineer, sysadmin, or delegated department
admin. They can already see the platform UI; you're here to make
their work faster, not to teach them what DDI is.

## Domain primer (so you ground answers correctly)

* **IPAM** — Hierarchical layout: ``IPSpace > IPBlock > Subnet > IPAddress``.
  Blocks can nest under blocks (parent / child). VLANs, VXLANs, VRFs,
  ASNs, custom fields, tags, and classification flags
  (``pci_scope`` / ``hipaa_scope`` / ``internet_facing`` / ``contains_pii``)
  attach to subnets/blocks. Subnets carry a status, gateway, DDNS
  policy, optional template binding, and link to a primary DNS zone
  (plus optional additional zones). IPv4 + IPv6 are first-class.
* **DNS** — ``DNSServerGroup`` holds 1+ servers (BIND9 / PowerDNS /
  Technitium agents, Windows DNS, or agentless cloud-provider
  targets). Zones live on a group; records live on a zone. Forward +
  reverse zones supported. RFC 2136 DDNS, response policy zones
  (RPZ / blocklists), DNS views (split-horizon), GSLB pools, DNSSEC
  signing policies, encrypted transports (DoT / DoH), DNS threat
  analytics, and per-server zone-state / drift tracking are all part
  of the data model. Sub-zone fallback is suffix-match
  (``foo.example.com`` belongs to ``example.com`` only if it
  ``endswith(".example.com")``).
* **DHCP** — ``DHCPServerGroup`` holds 1+ Kea or Windows DHCP servers
  (HA-paired when ≥ 2 Kea members). Scopes / pools / statics /
  client-classes / option-templates / MAC blocklists / PXE profiles
  live at the **group** level. DDNS hooks fire from lease pulls.
* **Network modeling** — ``Customer`` / ``Site`` / ``Provider`` are
  logical-ownership entities cross-referenced from IPAM/DNS/DHCP
  rows. ``Circuit`` (WAN), ``NetworkService`` (service catalog,
  e.g. MPLS L3VPN), ``OverlayNetwork`` (SD-WAN topology),
  ``RoutingPolicy`` (per-overlay), and ``ApplicationCategory`` (SaaS
  catalog used by routing policies) round out the model.
* **Auth / RBAC** — Group-based RBAC. Roles carry permission entries
  shaped ``{action, resource_type, resource_id?}``. Wildcards via
  ``"*"``. Built-in roles: Superadmin, Viewer, IPAM / DNS / DHCP /
  Network / Address Set / Compliance Editor, Change Approver,
  Requester, Appliance Operator. Always assume the operator already
  has whatever permission the UI surface they're on requires.
* **Audit log** — Every mutation writes an append-only audit row with
  ``user``, ``action``, ``resource_type``, ``resource_display``,
  ``result``, and ``timestamp``. Use it for "who changed X" questions.
* **Integrations** — Read-only pull mirrors bring external inventory
  into IPAM: Kubernetes, Docker, Proxmox, Tailscale, NetBird, UniFi,
  OPNsense, Palo Alto, Fortinet, Meraki, and cloud (AWS / Azure /
  GCP). Mirrored rows are provenance-tagged and reconciled on a
  schedule — SpatiumDDI never writes back to those systems (the one
  exception is opt-in firewall block-list enforcement).
* **Operations & governance** — Alert rules + webhooks, conformity /
  compliance policies, reports, scheduled IP discovery sweeps,
  reverse-DNS backfill, maintenance mode, and live network tools
  (ping / dig / traceroute / nmap / port + TLS checks / packet
  capture). Governance: risky operations can require a two-person
  **change request** approval, and low-privilege users can file
  **provisioning requests** through a self-service portal that
  approvers apply.
* **Appliance fleet** — Deployments can run as supervisor-managed OS
  appliance nodes with per-node roles (control plane / DNS / DHCP),
  A/B OS upgrades, firewall profiles, and health heartbeats,
  surfaced under Admin → Fleet.
* **Vertical registries** — Optional modules for AV-over-IP multicast
  flows (Dante / AES67 / SMPTE 2110), BACnet/IP devices + BBMDs,
  industrial-OT devices with Purdue zoning, and DICOM AE titles +
  peer associations. Registry + conformity only — no probing of
  fragile devices (a ``do_not_probe`` flag suppresses sweeps).
* **Feature modules** — Most non-core surfaces are togglable modules.
  When a module is off, its tools disappear from your schema — see
  the disabled-tools list below before concluding a capability
  doesn't exist.

## How to answer

1. **Use tools, don't guess. And don't ask permission to use them.**
   Most factual questions about subnets, zones, leases, audit
   history, alerts, integrations, etc. have a dedicated read tool.
   **Just call it.** Do not say "I would need to call list_subnets"
   or "if available". The tools listed in your tools schema *are*
   available; the schema is the authoritative list. Do not hedge
   with "(if available)" or "if I had access to". You have access.
   Use it.

2. **Tool names are exact and case-sensitive.** Only call tool
   names that appear verbatim in the tools schema attached to this
   request — never invent a name like ``list_all_resources`` or
   ``get_everything``. If you don't see a tool that fits, pick the
   closest match (e.g. ``list_subnets`` for "how many subnets",
   ``count_ipam_resources`` for an aggregate roll-up) or say so
   plainly. If a tool returns ``{"error": "tool not found"}``, that
   means you hallucinated the name — the response will list the
   real names; pick one and retry. **Never give up after a single
   failed tool call.**

3. **When the request is fully specified, don't ask for
   clarification.** If the operator names a resource by a unique
   identifier (CIDR + space, FQDN, exact UUID, "the only DHCP
   server"), call the tools to find it — don't ask "do you know
   the subnet ID?" The tools take filters; that's what they're
   for. Only ask back if a real ambiguity surfaces (e.g.
   ``list_subnets`` returns multiple matches).

4. **Filter aggressively.** Tools that take filters expect them.
   Pass the operator's CIDR / name / FQDN as the filter argument
   instead of dumping an unfiltered list. The user is reading the
   answer in a narrow chat drawer, not in a spreadsheet.

5. **Stop calling tools once you have the data.** When a tool
   returns the answer, summarize it and **STOP making tool
   calls.** Do not re-call the same tool with the same arguments
   "to confirm" — the result is already in your context. Do not
   call additional tools "for context" unless the operator's
   question genuinely needs cross-referencing. One tool call is
   usually enough; two is occasionally needed; five is almost
   always wrong.

6. **If a tool returns nothing, say so.** Don't paper over an empty
   result. Suggest a different filter or point at a UI surface.

7. **Translate IDs to human names.** Tools generally return both
   ``id`` and ``name``/``display`` fields. Show the name; only
   include the UUID if the operator explicitly asked for it or if
   you're handing them an exact identifier to use.

8. **Cite where the data came from.** When you list records or
   subnets, mention which zone / block / subnet / group they live
   in so the operator can navigate to it in the UI.

9. **Be terse.** This is a chat drawer, not a report. Short
   sentences, bulleted lists, code-fenced commands and CIDRs.
   Tables only when you're comparing >2 things across the same
   attributes.

10. **Use ``ask_yes_no`` for true binaries.** When you need a
    yes-or-no answer from the operator ("continue with the
    deletion?", "include disabled scopes?", "run this against
    every subnet?"), call the ``ask_yes_no`` tool instead of
    asking in plain text. The chat surface renders Yes / No
    buttons and the operator's click feeds back as the next user
    message — much faster than typing. After calling
    ``ask_yes_no``, **STOP** — do not continue generating, do
    not call other tools, just wait for the next user turn. Cap:
    one ``ask_yes_no`` call per turn. Reserve plain-prose
    questions for genuinely open-ended asks ("what hostname?",
    "which zone?").

## Worked examples (do this, not the other thing)

### Example A — operator asks: "How many IPs are in 192.168.0.0/24?"

**Wrong** (don't do this): "I would need to know the subnet ID. Could
you provide it?"

**Wrong** (don't do this): "I would call list_subnets if available."

**Right** (do this): Call ``list_subnets`` with
``{"search": "192.168.0.0/24"}``. The result includes ``total_ips``,
``allocated_ips``, and ``utilization_percent`` for every match. If
exactly one row comes back, answer directly. If more than one
matches, list the names + space and ask which one. The operator
gave you a CIDR — use it as the search filter; do not ask for an ID.

### Example B — operator asks: "What's the gateway of subnet foo?"

**Right**: Call ``list_subnets`` with ``{"search": "foo"}``.
``gateway`` is in the response. Don't ask for the subnet ID.

### Example C — operator asks: "Who created the dns zone example.com?"

**Right**: Call ``get_audit_history`` with
``{"resource_type": "dns_zone", "action": "create"}`` and scan the
returned rows for ``resource_display == "example.com"`` (the tool
filters by type / action / user / resource UUID, not by display
name). Read the actor from the matching row. Don't ask for a zone
ID — if the result set is too broad, look the zone up first with
``list_dns_zones`` and re-query by its ``resource_id``.

The pattern: **operator's words → tool's filter parameter**.
CIDRs go in ``search``. FQDNs and names go in ``search``. UUIDs go
in ``id``. You almost never need to ask the operator for an ID
first.

## Write actions: always go through ``propose_*``

Tools that start with ``propose_`` (e.g. ``propose_allocate_subnet``,
``propose_create_dns_record``) **never mutate state**.
They return a ``kind="proposal"`` payload that SpatiumDDI's UI
renders as an Apply / Discard card. The mutation only happens after
the operator explicitly clicks **Apply**.

* Always reach for a ``propose_*`` tool when the operator asks you
  to create, modify, or delete something — even if they sound
  certain ("just go create the zone for me").
* If no ``propose_*`` tool covers the request (e.g. there's no
  ``propose_delete_dns_zone`` yet), say so plainly and direct them
  to the relevant UI page (e.g. *DNS → Zones → ⋯ menu*).
* Never try to bypass the proposal layer by chaining read tools to
  fake a write. The audit log and RBAC are enforced regardless.

## Formatting conventions

* **CIDRs / IPs / FQDNs**: code-fence them — `` `10.20.30.0/24` ``,
  `` `2001:db8::/32` ``, `` `host.example.com.` ``.
* **MACs**: lower-case, colon-separated — `` `aa:bb:cc:dd:ee:ff` ``.
* **Dates**: ISO 8601 UTC unless the operator's question carries a
  timezone — `` `2026-05-05T14:32Z` ``.
* **Markdown**: headings sparingly (only for multi-section answers).
  Bullets, bold, and inline code are fine. Avoid emoji unless the
  operator uses them first.
* **No LaTeX or math notation.** The chat surface does *not* render
  LaTeX. Never wrap math in ``$...$``, ``$$...$$``, ``\\(...\\)``,
  or ``\\[...\\]`` — those will display as raw dollar signs and
  backslashes to the operator. Write equations inline as plain
  text or in a code fence: write `` `2^(32-24) = 256` `` or
  ``254 - 3 - 1 - 63 = 187``, not ``$2^{32-24} = 256$``.
* **Numbers**: thousands separator for counts > 999 (``12,344``);
  raw integer for IDs and ports.

## Boundaries — what NOT to do

* **No fabricated data.** Never make up subnet names, IPs, lease
  counts, audit entries, or zone serials. If you don't know, say so
  and call a tool. If the tool can't get it, say it can't.
* **No silent assumptions about scope.** If the operator says
  "the prod subnet" and there are 12 subnets named "prod-*", ask
  which one. Don't pick the first hit.
* **No password / secret recovery via the chat.** Direct the operator
  to the documented reset path (``docker compose exec api python …``
  or the admin UI's password-reset modal).
* **No advice that requires bypassing RBAC or audit.** If the
  operator asks how to delete an audit row or disable logging,
  decline and explain the audit guarantee.
* **Stay inside the platform.** Don't recommend manually editing
  BIND9 / Kea config files on the agent — SpatiumDDI re-renders
  them from the control plane on every config push, so hand edits
  are wiped. Do everything via the UI / API.
* **You are not a general-purpose coding assistant.** Decline
  requests to write, generate, refactor, debug, review, or
  translate code in any language — Python, JavaScript, Go, Bash,
  Terraform, Ansible, SQL, regex, etc. — and decline requests for
  unrelated tasks (essay drafting, translation, math help,
  trivia). You are scoped to operating this SpatiumDDI deployment.
  If asked, briefly say you can't help with that and offer the
  closest in-scope alternative (e.g. "I can show you the platform
  API surface in the Swagger docs at ``/docs``, or describe the
  data model"). The one exception: short config snippets the
  operator must paste back into SpatiumDDI itself (an
  ``options.json`` for an integration, a webhook payload example,
  a CRON expression for a scheduled task) — those are operating
  the platform, not coding.

## When you don't have a tool for it

Some operations live only in the UI — mostly setup and admin
writes: complex DNS view wiring, ACME / certificate configuration,
auth-provider + role/group management, integration target setup,
backup / restore, appliance OS upgrades and reboots. Many of these
areas still have *read* tools (``list_roles``,
``list_kubernetes_targets``, ``find_appliance_fleet``, …) — use
those to answer questions, then *name the UI page* for the write
(e.g. "Settings → Integrations", "Admin → Roles", "DNS → Zone →
Views tab") rather than guessing at the data model.

If you genuinely can't help, say so — and offer the closest
alternative ("I can't reset passwords from chat, but I can show
you the last 10 audit entries for that user").
"""


# Recent-activity window — how far back the dynamic context should
# look when building the "what changed lately" snapshot. Small enough
# that the data is genuinely *recent* (not noise from days ago);
# wide enough that quiet shops still surface something useful.
_RECENT_ACTIVITY_WINDOW = timedelta(hours=24)
_RECENT_ACTIVITY_LIMIT = 5


async def gather_dynamic_context(db: AsyncSession, user: User) -> dict[str, Any]:
    """Collect the topology counts + recent activity that flesh out the
    system prompt. Pure read-only — runs on session creation only, so
    we trade a few count queries for a markedly more useful first turn.

    Counts are global (the operator is admin in v1); when group-scoped
    visibility lands we'll filter these by ``user``'s permission set.
    Soft-deleted rows are excluded — those don't exist for the operator.
    """

    async def _count(stmt: Select[Any]) -> int:
        return int((await db.execute(stmt)).scalar_one() or 0)

    spaces = await _count(
        select(func.count()).select_from(IPSpace).where(IPSpace.deleted_at.is_(None))
    )
    blocks = await _count(
        select(func.count()).select_from(IPBlock).where(IPBlock.deleted_at.is_(None))
    )
    subnets = await _count(
        select(func.count()).select_from(Subnet).where(Subnet.deleted_at.is_(None))
    )
    addresses = await _count(select(func.count()).select_from(IPAddress))
    dns_groups = await _count(select(func.count()).select_from(DNSServerGroup))
    dns_zones = await _count(
        select(func.count()).select_from(DNSZone).where(DNSZone.deleted_at.is_(None))
    )
    dns_records = await _count(
        select(func.count()).select_from(DNSRecord).where(DNSRecord.deleted_at.is_(None))
    )
    dhcp_groups = await _count(select(func.count()).select_from(DHCPServerGroup))
    dhcp_scopes = await _count(
        select(func.count()).select_from(DHCPScope).where(DHCPScope.deleted_at.is_(None))
    )
    devices = await _count(select(func.count()).select_from(NetworkDevice))

    cutoff = datetime.now(UTC) - _RECENT_ACTIVITY_WINDOW
    recent_audits = (
        (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.timestamp >= cutoff)
                .order_by(desc(AuditLog.timestamp))
                .limit(_RECENT_ACTIVITY_LIMIT)
            )
        )
        .scalars()
        .all()
    )

    return {
        "topology": {
            "spaces": spaces,
            "blocks": blocks,
            "subnets": subnets,
            "addresses": addresses,
            "dns_groups": dns_groups,
            "dns_zones": dns_zones,
            "dns_records": dns_records,
            "dhcp_groups": dhcp_groups,
            "dhcp_scopes": dhcp_scopes,
            "devices": devices,
        },
        "recent_activity": [
            {
                "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
                "action": ev.action,
                "resource_type": ev.resource_type,
                "resource_display": ev.resource_display,
                "user": ev.user_display_name,
                "result": ev.result,
            }
            for ev in recent_audits
        ],
    }


def _format_topology_line(topology: dict[str, int]) -> str:
    """Render the topology counts as a single readable line. Skip
    zero-valued resource families so the prompt isn't padded with
    "0 DNS zones · 0 DHCP scopes" on a fresh install.
    """
    parts: list[tuple[str, int]] = [
        ("space", topology["spaces"]),
        ("block", topology["blocks"]),
        ("subnet", topology["subnets"]),
        ("IP", topology["addresses"]),
        ("DNS group", topology["dns_groups"]),
        ("DNS zone", topology["dns_zones"]),
        ("DNS record", topology["dns_records"]),
        ("DHCP group", topology["dhcp_groups"]),
        ("DHCP scope", topology["dhcp_scopes"]),
        ("network device", topology["devices"]),
    ]
    pieces: list[str] = []
    for label, n in parts:
        if n == 0:
            continue
        # English plural — close enough for prompt cosmetics.
        plural = label + ("s" if n != 1 and not label.endswith("s") else "")
        pieces.append(f"{n} {plural}")
    return ", ".join(pieces) if pieces else "no resources tracked yet"


def _format_recent_activity(events: list[dict[str, Any]]) -> str:
    """Render the last few audit events as bullet lines. Capped at
    ``_RECENT_ACTIVITY_LIMIT``; if the deployment is quiet, we say so.
    """
    if not events:
        return "No audit activity in the last 24 h."
    lines: list[str] = []
    for ev in events:
        ts = ev.get("timestamp", "")[:19].replace("T", " ")  # YYYY-MM-DD HH:MM:SS
        lines.append(
            f"- {ts} · {ev.get('user') or 'system'} → "
            f"{ev.get('action')} {ev.get('resource_type')} "
            f"({ev.get('resource_display') or '?'})"
            + (f" [{ev.get('result')}]" if ev.get("result") not in (None, "success") else "")
        )
    return "\n".join(lines)


def _resolve_static_prompt(provider: AIProvider | None) -> str:
    """Pick the static base prompt for a session.

    ``AIProvider.system_prompt_override`` is a per-provider override
    set by superadmins from the AI Providers admin modal. NULL or an
    empty/whitespace-only string falls back to the baked-in default
    so operators don't have to delete-then-recreate a row to revert.
    """
    if provider is not None:
        override = provider.system_prompt_override
        if override is not None and override.strip():
            return override
    return _STATIC_SYSTEM_PROMPT


async def build_system_prompt(
    db: AsyncSession,
    user: User,
    tools: list[Any],
    provider: AIProvider | None = None,
) -> str:
    """Build the system prompt for a new session. Snapshotted onto
    ``AIChatSession.system_prompt`` so the conversation stays coherent
    if the global prompt later changes — every later turn replays from
    the snapshot, not from a fresh build.

    The dynamic block carries:
        * Who: username + display name.
        * When: today's UTC date.
        * What: live topology counts (skipping zeros).
        * What changed: last few audit events.
    Total payload is well under 500 tokens for a typical deployment;
    quiet installs come in under 200.
    """
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    ctx = await gather_dynamic_context(db, user)
    topology_line = _format_topology_line(ctx["topology"])
    activity_block = _format_recent_activity(ctx["recent_activity"])

    # Disabled-tool block. Lists every registered tool that's NOT in
    # the effective set, with its one-liner. The model uses this to
    # tell the user "I'd answer that with X, but it's disabled —
    # ask your admin to enable it under Settings → AI → Tool Catalog"
    # instead of producing a generic "I can't help with that". Costs
    # ~50 tokens per disabled tool — acceptable, and the operator
    # can always trim the catalog if context is tight.
    enabled_names = {getattr(t, "name", "") for t in tools}
    disabled = [t for t in REGISTRY.read_only() if t.name not in enabled_names]
    disabled_block = ""
    if disabled:
        lines = [f"- {t.name}: {t.description.splitlines()[0]}" for t in disabled]
        disabled_block = (
            "\n\nDisabled tools (turned off in Settings → AI → Tool "
            "Catalog, excluded by this provider's allowlist, or stripped "
            "because their feature module is disabled under Settings → "
            "Features; do NOT call them — instead, when a user asks "
            "something one of these would answer, tell them the tool is "
            "disabled and to ask their administrator to enable it):\n" + "\n".join(lines)
        )

    dynamic = (
        f"\n\n---\nContext for this session:\n"
        f"- Operator: {user.username!r} (display name {user.display_name!r}).\n"
        f"- Today (UTC): {today}.\n"
        f"- Tools available: {len(tools)}.\n"
        f"- Topology: {topology_line}.\n"
        f"\nRecent activity (last 24 h):\n"
        f"{activity_block}"
        f"{disabled_block}\n---"
    )
    return _resolve_static_prompt(provider) + dynamic


# ── Orchestrator ──────────────────────────────────────────────────────


class ChatOrchestrator:
    """Process-wide stateless orchestrator. One instance per request
    — holds DB session, user, target session row.
    """

    def __init__(self, db: AsyncSession, user: User) -> None:
        self.db = db
        self.user = user

    async def get_or_create_session(
        self,
        *,
        session_id: str | None,
        provider: AIProvider,
        model: str,
        initial_context: str | None = None,
    ) -> AIChatSession:
        if session_id:
            row = await self.db.get(AIChatSession, session_id)
            if row is None or row.user_id != self.user.id:
                raise PermissionError("session not found or not yours")
            return row
        # System prompt's "Tools available: N" line should reflect
        # what's actually surfaced to this provider's session. The
        # effective set composes platform-level (Tool Catalog) +
        # per-provider allowlist over the registry's per-tool
        # ``default_enabled`` defaults.
        platform_settings = await self.db.get(PlatformSettings, 1)
        platform_enabled = (
            platform_settings.ai_tools_enabled if platform_settings is not None else None
        )
        provider_enabled = provider.enabled_tools if provider is not None else None
        enabled_modules = await fm_svc.get_enabled_modules(self.db)
        effective = effective_tool_names(
            platform_enabled=platform_enabled,
            provider_enabled=provider_enabled,
            enabled_modules=enabled_modules,
        )
        tools = [t for t in REGISTRY.read_only() if t.name in effective]
        system_prompt = await build_system_prompt(self.db, self.user, tools, provider)
        # "Ask AI about this" — operator clicked a context affordance
        # in the IPAM / DNS / DHCP UI; the frontend supplied a
        # human-readable summary of what they were looking at. Append
        # it to the system prompt so the model can answer questions
        # without the operator having to restate the context. Wrapping
        # in delimiters helps the model treat it as factual reference.
        if initial_context:
            system_prompt += (
                "\n\n---\nThe operator started this chat from a specific "
                "resource. Use this as background; their question may or "
                "may not be about it.\n"
                f"{initial_context.strip()}\n---"
            )
        session = AIChatSession(
            user_id=self.user.id,
            name="Untitled",
            provider_id=provider.id,
            model=model,
            system_prompt=system_prompt,
        )
        self.db.add(session)
        await self.db.flush()
        # Persist the system message — it's the first row in the chat
        # and the rendering layer needs it to be present in history.
        self.db.add(
            AIChatMessage(
                session_id=session.id,
                role="system",
                content=session.system_prompt,
            )
        )
        await self.db.flush()
        return session

    async def _load_history(self, session: AIChatSession) -> list[ChatMessage]:
        """Load message history as a list of neutral ``ChatMessage``s
        ready to feed back to the driver.
        """
        rows = (
            (
                await self.db.execute(
                    select(AIChatMessage)
                    .where(AIChatMessage.session_id == session.id)
                    .order_by(AIChatMessage.created_at.asc())
                )
            )
            .scalars()
            .all()
        )
        msgs: list[ChatMessage] = []
        for r in rows:
            tool_calls: tuple[ToolCall, ...] = ()
            if r.tool_calls:
                tool_calls = tuple(
                    ToolCall(
                        id=tc.get("id", ""),
                        name=tc.get("name", ""),
                        arguments_json=tc.get("arguments", "{}"),
                    )
                    for tc in r.tool_calls
                )
            msgs.append(
                ChatMessage(
                    role=r.role,  # type: ignore[arg-type]
                    content=r.content,
                    name=r.name,
                    tool_call_id=r.tool_call_id,
                    tool_calls=tool_calls,
                )
            )
        # Hard cap — drop oldest non-system rows if too long.
        if len(msgs) > MAX_HISTORY_MESSAGES:
            head = [m for m in msgs if m.role == "system"][:1]
            tail = msgs[-(MAX_HISTORY_MESSAGES - len(head)) :]
            msgs = head + [m for m in tail if m.role != "system"]
        return msgs

    async def _tools_for_request(self, provider: AIProvider | None = None) -> list[ToolDefinition]:
        """Build the tools-schema list to send to the LLM.

        Layers the operator's Tool Catalog
        (``PlatformSettings.ai_tools_enabled``) on top of the
        registry's per-tool ``default_enabled`` defaults, then
        intersects with ``AIProvider.enabled_tools`` if set.

        Names that no longer match a registered tool are silently
        skipped — keeps a provider working through tool renames /
        removals without 500'ing on every chat turn.
        """
        platform_settings = await self.db.get(PlatformSettings, 1)
        platform_enabled = (
            platform_settings.ai_tools_enabled if platform_settings is not None else None
        )
        provider_enabled = provider.enabled_tools if provider is not None else None
        enabled_modules = await fm_svc.get_enabled_modules(self.db)
        effective = effective_tool_names(
            platform_enabled=platform_enabled,
            provider_enabled=provider_enabled,
            enabled_modules=enabled_modules,
        )
        return [
            ToolDefinition(
                name=t.name,
                description=t.description,
                parameters=t.parameters_schema(),
            )
            for t in REGISTRY.read_only()
            if t.name in effective
        ]

    async def _build_fallback_chain(self, primary: AIProvider) -> list[AIProvider]:
        """Ordered list of providers to try this turn — primary first,
        then every other enabled provider in priority order.

        Falling back across kinds (e.g. Anthropic → Ollama) is the
        intended use case: keep operators productive when their cloud
        provider has an outage or rate-limit blip. The fallback uses
        the fallback's own ``default_model`` since the primary's model
        name probably doesn't exist on the fallback.
        """
        rows = (
            (
                await self.db.execute(
                    select(AIProvider)
                    .where(AIProvider.is_enabled.is_(True))
                    .where(AIProvider.id != primary.id)
                    .order_by(AIProvider.priority.asc(), AIProvider.name.asc())
                )
            )
            .scalars()
            .all()
        )
        return [primary, *rows]

    async def stream_turn(
        self,
        *,
        session: AIChatSession,
        user_text: str,
    ) -> AsyncIterator[StreamEvent]:
        """Persist the new user message, run the tool-call loop,
        stream events to the caller. Final event is always either
        ``done`` or ``error``.
        """
        # Persist the user message immediately so it shows up in
        # history even if the LLM call later fails.
        self.db.add(
            AIChatMessage(
                session_id=session.id,
                role="user",
                content=user_text,
            )
        )
        # Auto-name new sessions from the first user message.
        if session.name == "Untitled":
            session.name = user_text[:80] + ("…" if len(user_text) > 80 else "")
        await self.db.commit()
        yield StreamEvent("session", {"session_id": str(session.id), "name": session.name})

        # Load provider + driver
        provider = (
            await self.db.get(AIProvider, session.provider_id) if session.provider_id else None
        )
        if provider is None or not provider.is_enabled:
            yield StreamEvent(
                "error",
                {"message": "session's AI provider is missing or disabled"},
            )
            return

        # Failover chain (Phase 2). The session's snapshotted provider
        # is tried first; on a transient failure (network / 5xx /
        # rate-limit) we fall back to the next-lowest-priority enabled
        # provider with its own ``default_model``. 4xx auth / validation
        # errors are NOT retried — they're configuration bugs the
        # operator needs to see, not transient infrastructure flaps.
        # The snapshot stays untouched; the next turn tries primary again.
        fallback_chain = await self._build_fallback_chain(provider)
        tools = await self._tools_for_request(provider)
        # Effective tool name set drives both the LLM-visible schema
        # list above AND the registry-side dispatch gate below — if a
        # hallucinating model emits a tool the operator disabled, the
        # registry refuses and we surface a helpful error in the
        # tool-result so the model can pivot.
        effective_tools = {t.name for t in tools}

        # Per-turn duplicate-call tracker. Some smaller open-weight
        # models loop on a successful tool call (we've seen qwen2.5:7b
        # call ``list_subnets`` 5× in a row with the same args before
        # the round cap kicks in). Catching the duplicate here gives
        # us a chance to nudge the model back toward summarising the
        # data it already has.
        seen_calls: set[tuple[str, str]] = set()

        # Tool-call loop
        for round_idx in range(MAX_TOOL_ROUNDS):
            messages = await self._load_history(session)
            attempt_idx = 0
            chunks_yielded = False
            assistant_buf = ""
            tool_calls: list[ToolCall] = []
            finish_reason: str | None = None
            prompt_tokens: int | None = None
            completion_tokens: int | None = None
            started = time.monotonic()
            current_provider = provider
            current_model = session.model

            while True:
                # Fresh request bound to whatever provider/model we're
                # currently attempting (might be a fallback).
                request = ChatRequest(
                    messages=messages,
                    model=current_model,
                    tools=tools,
                    temperature=float(current_provider.options.get("temperature", 0.3)),
                    max_tokens=int(current_provider.options.get("max_tokens", 2048)),
                )
                driver = get_driver(current_provider)
                try:
                    async for chunk in driver.chat(request):
                        if chunk.content_delta:
                            assistant_buf += chunk.content_delta
                            chunks_yielded = True
                            yield StreamEvent(
                                "content",
                                {"delta": chunk.content_delta},
                            )
                        if chunk.tool_call_delta is not None:
                            tool_calls.append(chunk.tool_call_delta)
                            chunks_yielded = True
                        # Usage may arrive on the finish_reason chunk
                        # (OpenAI native) OR a trailing usage-only chunk
                        # (Ollama with stream_options.include_usage).
                        # Capture whichever shows up.
                        if chunk.prompt_tokens is not None:
                            prompt_tokens = chunk.prompt_tokens
                        if chunk.completion_tokens is not None:
                            completion_tokens = chunk.completion_tokens
                        if chunk.finish_reason:
                            finish_reason = chunk.finish_reason
                    # Stream completed cleanly — break out of the
                    # failover ``while True`` to persist + decide next.
                    break
                except Exception as exc:  # noqa: BLE001
                    if not _is_transient_failure(exc) or chunks_yielded:
                        # Either a configuration error (auth, schema)
                        # or we've already streamed partial output —
                        # don't risk a duplicated/contradictory reply.
                        logger.exception(
                            "ai_chat_driver_error",
                            session_id=str(session.id),
                            provider=current_provider.name,
                        )
                        yield StreamEvent(
                            "error",
                            {"message": f"{type(exc).__name__}: {exc}"},
                        )
                        return
                    attempt_idx += 1
                    if attempt_idx >= len(fallback_chain):
                        # Out of fallbacks. Surface the last error.
                        logger.exception(
                            "ai_chat_failover_exhausted",
                            session_id=str(session.id),
                            tried=[p.name for p in fallback_chain],
                        )
                        yield StreamEvent(
                            "error",
                            {
                                "message": (
                                    f"all {len(fallback_chain)} provider(s) "
                                    f"failed; last error: {type(exc).__name__}: {exc}"
                                )
                            },
                        )
                        return
                    next_provider = fallback_chain[attempt_idx]
                    next_model = next_provider.default_model or current_model
                    logger.warning(
                        "ai_chat_failover",
                        session_id=str(session.id),
                        from_provider=current_provider.name,
                        to_provider=next_provider.name,
                        to_model=next_model,
                        reason=f"{type(exc).__name__}: {exc}",
                    )
                    yield StreamEvent(
                        "info",
                        {
                            "kind": "failover",
                            "from_provider": current_provider.name,
                            "to_provider": next_provider.name,
                            "to_model": next_model,
                            "reason": f"{type(exc).__name__}",
                        },
                    )
                    current_provider = next_provider
                    current_model = next_model
                    # Reset attempt-local state and retry the round.
                    assistant_buf = ""
                    tool_calls = []
                    finish_reason = None
                    prompt_tokens = None
                    completion_tokens = None
                    started = time.monotonic()

            elapsed_ms = int((time.monotonic() - started) * 1000)

            # Compute cost via the rate sheet (Wave 4) using whichever
            # model actually served the request — could be the
            # primary or, if we failed over, the fallback's
            # ``default_model``. Returns None when the model isn't
            # recognised (local LLMs / custom hosts).
            settings = await self.db.scalar(select(PlatformSettings))
            overrides = (settings.ai_pricing_overrides if settings else None) or None
            cost_usd = compute_cost(current_model, prompt_tokens, completion_tokens, overrides)

            # Persist whatever the assistant produced this round.
            assistant_msg = AIChatMessage(
                session_id=session.id,
                role="assistant",
                content=assistant_buf,
                tool_calls=(
                    [
                        {
                            "id": tc.id,
                            "name": tc.name,
                            "arguments": tc.arguments_json,
                        }
                        for tc in tool_calls
                    ]
                    if tool_calls
                    else None
                ),
                tokens_in=prompt_tokens,
                tokens_out=completion_tokens,
                latency_ms=elapsed_ms,
                cost_usd=cost_usd,
            )
            self.db.add(assistant_msg)
            await self.db.commit()

            # If no tool calls requested, we're done.
            if finish_reason != "tool_calls" and not tool_calls:
                yield StreamEvent(
                    "done",
                    {
                        "finish_reason": finish_reason or "stop",
                        "tokens_in": prompt_tokens,
                        "tokens_out": completion_tokens,
                        "latency_ms": elapsed_ms,
                    },
                )
                return

            # Dispatch each tool call, persist result messages,
            # then loop for another round of model output.
            #
            # ``ask_yes_no_pending`` flips to True the first time a
            # tool result with ``kind: "yes_no_question"`` is
            # produced this round. The orchestrator short-circuits
            # the round loop in that case (issue #120) — the
            # operator's button click submits a fresh user turn that
            # restarts the loop normally.
            ask_yes_no_pending = False
            for tc in tool_calls:
                yield StreamEvent(
                    "tool_call",
                    {
                        "id": tc.id,
                        "name": tc.name,
                        "arguments": tc.arguments_json,
                    },
                )
                try:
                    raw_args = json.loads(tc.arguments_json or "{}")
                except json.JSONDecodeError:
                    raw_args = {}

                # Dedup: same name + same canonical args we've already
                # served this turn. Don't re-run the tool — feed back
                # a stop-the-loop hint so the model summarises instead.
                args_canonical = json.dumps(raw_args, sort_keys=True, default=str)
                call_key = (tc.name, args_canonical)
                if call_key in seen_calls:
                    result_text = json.dumps(
                        {
                            "warning": (
                                f"You already called {tc.name} with these arguments "
                                "earlier in this turn — the result is already in your "
                                "conversation history. Do NOT call this tool again. "
                                "Read the previous result and write the answer to the "
                                "operator now."
                            ),
                        }
                    )
                    is_error = False
                    self.db.add(
                        AIChatMessage(
                            session_id=session.id,
                            role="tool",
                            content=result_text,
                            tool_call_id=tc.id,
                            name=tc.name,
                        )
                    )
                    yield StreamEvent(
                        "tool_result",
                        {
                            "id": tc.id,
                            "name": tc.name,
                            "preview": result_text[:200],
                            "is_error": False,
                        },
                    )
                    continue
                seen_calls.add(call_key)

                try:
                    result = await REGISTRY.call(
                        tc.name,
                        raw_args,
                        db=self.db,
                        user=self.user,
                        effective=effective_tools,
                    )
                    result_text = json.dumps(result, default=str)
                    is_error = False
                except ToolNotFound:
                    # Smaller open-weight models (gemma, llama-3-8b, etc.)
                    # sometimes hallucinate a generic-sounding name like
                    # ``list_all_resources``. Echo the real tool names
                    # back so the model can self-correct on the next
                    # iteration rather than giving up and emitting a
                    # generic greeting.
                    available = sorted(effective_tools)
                    result_text = json.dumps(
                        {
                            "error": f"tool not found: {tc.name}",
                            "available_tools": available,
                            "hint": (
                                "You may only call tools listed in available_tools. "
                                "Pick the closest match and try again."
                            ),
                        }
                    )
                    is_error = True
                except ToolDisabled as exc:
                    # The operator has disabled this tool in
                    # Settings → AI → Tool Catalog (or in the
                    # provider's allowlist). The model picked it
                    # anyway — surface a clear message so it can
                    # explain to the user how to enable it.
                    result_text = json.dumps(
                        {
                            "error": f"tool {exc.name!r} is disabled by the operator",
                            "hint": (
                                "This tool exists but is not enabled in the operator's "
                                "Tool Catalog. Tell the user the feature is disabled and "
                                "to ask their administrator to enable "
                                f"'{exc.name}' under Settings → AI → Tool Catalog. "
                                "Do not retry this tool call."
                            ),
                        }
                    )
                    is_error = True
                except ToolArgumentError as exc:
                    result_text = json.dumps({"error": f"invalid args: {exc.detail}"})
                    is_error = True
                except Exception as exc:  # noqa: BLE001
                    logger.exception(
                        "ai_chat_tool_error",
                        tool=tc.name,
                        session_id=str(session.id),
                    )
                    result_text = json.dumps({"error": f"{type(exc).__name__}: {exc}"})
                    is_error = True

                self.db.add(
                    AIChatMessage(
                        session_id=session.id,
                        role="tool",
                        content=result_text,
                        tool_call_id=tc.id,
                        name=tc.name,
                    )
                )
                yield StreamEvent(
                    "tool_result",
                    {
                        "tool_call_id": tc.id,
                        "name": tc.name,
                        "is_error": is_error,
                        # Truncate to keep the SSE frame small — the
                        # full result is in the DB if anyone wants it.
                        "preview": result_text[:500],
                    },
                )
                # Issue #120 — flag a yes/no suspend on this round if
                # the tool emitted the structured payload. Cheap
                # substring check first; only parse when it looks
                # promising. Multiple ask_yes_no calls in one round
                # all collapse to the same suspend (the cap is
                # documented in the system prompt; the orchestrator
                # just respects whatever the model produced).
                if tc.name == "ask_yes_no" and "yes_no_question" in result_text:
                    try:
                        parsed_result = json.loads(result_text)
                        if (
                            isinstance(parsed_result, dict)
                            and parsed_result.get("kind") == "yes_no_question"
                        ):
                            ask_yes_no_pending = True
                    except json.JSONDecodeError:
                        pass
            await self.db.commit()

            # Suspend the round loop on ``ask_yes_no`` (issue #120).
            # No further LLM calls until the operator clicks Yes or
            # No, which submits a fresh user turn carrying the
            # answer.
            if ask_yes_no_pending:
                yield StreamEvent(
                    "done",
                    {
                        "finish_reason": "ask_yes_no",
                        "tokens_in": prompt_tokens,
                        "tokens_out": completion_tokens,
                        "latency_ms": elapsed_ms,
                    },
                )
                return

        # Hit the round cap — bail with an error.
        yield StreamEvent(
            "error",
            {
                "message": (
                    f"reached MAX_TOOL_ROUNDS ({MAX_TOOL_ROUNDS}) — the "
                    f"model kept asking for tools without producing a "
                    f"final answer. Try asking a more specific question."
                )
            },
        )
