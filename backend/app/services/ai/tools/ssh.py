"""Operator Copilot read tool for the appliance SSH surface (issue #157).

Surfaces the singleton ``platform_settings`` SSH config so an operator can
ask the Copilot "is password auth on?", "is root login allowed?", "what port
is sshd on?", "which keys are authorized?". Public keys are NOT secrets, so
this tool returns each key's name / comment / fingerprint (and the full
public key, which is safe to surface) — there is nothing to redact, unlike
the SNMP community / syslog CA PEM.

There is NO ``propose_*`` write tool — SSH config is changed through the
Appliance → SSH form, same as SNMP / syslog (those writes carry a lockout-
safety cross-check the form path enforces).

Also home to ``find_remote_access_doors`` (#1013), which reports the SSH
allow-list together with the Web UI one. Those are two independent settings
that compose into a console-only lockout, and no tool could see both: the Web
UI half sits on ``find_web_ui_access``, tagged ``module="appliance.firewall"``,
so with that module off the copilot cannot see it at all — while the SSH half
is plain host-config and always visible. It lives here rather than in
``tools/firewall.py`` so it inherits that always-visible shape.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import is_effective_superadmin
from app.models.auth import User
from app.models.settings import PlatformSettings
from app.services.ai.tools.base import register_tool
from app.services.appliance.access import effective_doors
from app.services.appliance.ssh import is_valid_public_key, key_fingerprint


class FindSshSettingsArgs(BaseModel):
    """No arguments — there is exactly one SSH config row."""

    pass


@register_tool(
    name="find_ssh_settings",
    permission="authenticated",
    description=(
        "Return the appliance SSH configuration: whether password "
        "authentication is enabled, whether root login is permitted, the sshd "
        "port, the allowed source-network CIDRs (the host firewall scopes the "
        "ssh port to these — empty means open from anywhere), and the list of "
        "authorized public keys (each with its operator label / comment / "
        "SHA256 fingerprint). Public keys are not secrets and are returned in "
        "full. Use to answer 'is password auth on?', 'is root login allowed?', "
        "'what port is sshd on?', 'which keys can log in?'. sshd runs on every "
        "SpatiumDDI appliance host; on docker / k8s deploys these settings "
        "still drive any registered appliance agents in a hybrid topology."
    ),
    args_model=FindSshSettingsArgs,
    category="admin",
    # Default enabled (NN #13) — read-only, no secrets (public keys are not
    # secret), no off-prem calls. module=None: SSH is plain host-config (like
    # SNMP / NTP / LLDP / syslog), not a feature module.
    default_enabled=True,
    module=None,
)
async def find_ssh_settings(
    db: AsyncSession, user: User, args: FindSshSettingsArgs
) -> dict[str, Any]:
    settings = await db.get(PlatformSettings, 1)
    if settings is None:
        return {"note": "platform_settings row missing"}
    keys = list(settings.ssh_authorized_keys or [])
    return {
        "password_auth_enabled": bool(settings.ssh_password_auth_enabled),
        "allow_root_login": bool(settings.ssh_allow_root_login),
        "port": int(settings.ssh_port or 22),
        "allowed_source_networks": list(settings.ssh_allowed_source_networks or []),
        # #1009 — the list above is what the operator typed; this is whether
        # it is in force. Reported as a pair rather than collapsed, because
        # "restricted to 10/8" and "would be restricted to 10/8 if enforced"
        # are opposite answers to "can this host be reached over SSH?" and
        # the copilot has no other way to tell them apart.
        "lockdown": bool(settings.ssh_lockdown),
        "source_restriction_enforced": bool(
            settings.ssh_lockdown and list(settings.ssh_allowed_source_networks or [])
        ),
        "authorized_keys": [
            {
                "name": (k.get("name") or "") if isinstance(k, dict) else "",
                "comment": (k.get("comment") or "") if isinstance(k, dict) else "",
                "public_key": (k.get("public_key") or "") if isinstance(k, dict) else "",
                "fingerprint": (
                    key_fingerprint(str(k.get("public_key") or "")) if isinstance(k, dict) else None
                ),
                "valid": (
                    is_valid_public_key(str(k.get("public_key") or ""))
                    if isinstance(k, dict)
                    else False
                ),
            }
            for k in keys
        ],
        # Aggregate signal for the LLM: is there at least one way in?
        # (password auth on OR at least one valid key) — mirrors the
        # lockout-safety invariant the form enforces.
        "lockout_safe": bool(settings.ssh_password_auth_enabled)
        or any(
            is_valid_public_key(str(k.get("public_key") or "")) for k in keys if isinstance(k, dict)
        ),
    }


def _superadmin_gate(user: User) -> dict[str, Any] | None:
    """Gate for :func:`find_remote_access_doors` only.

    It reports the Web UI allow-list, and ``find_web_ui_access`` — the only
    other tool that returns that list — is superadmin-gated. A tool is gated
    at the level of the most restricted datum it returns, so widening that
    list to every copilot user as a side effect of joining it to the SSH one
    would be a real (if quiet) change in who can read it.

    Deliberately NOT applied to ``find_ssh_settings`` above: that shipped
    ungated by decision (#157) and tightening it is a separate call, not
    something to fold into a lockout fix.
    """
    if not is_effective_superadmin(user):
        return {
            "error": (
                "Appliance source restrictions are restricted to superadmin "
                "users. Ask your platform admin to run the query."
            )
        }
    return None


class FindRemoteAccessDoorsArgs(BaseModel):
    """No arguments — both restrictions are singleton settings."""

    pass


@register_tool(
    name="find_remote_access_doors",
    permission="superadmin",
    description=(
        "Return BOTH appliance source restrictions together: the Web UI "
        "allow-list (web_ui_allowed_cidrs) and the SSH allow-list, with "
        "whether each is actually in force. Use to answer 'is this fleet at "
        "risk of a console-only lockout?', 'which networks can reach the "
        "appliance at all?', 'are both remote doors restricted?'. The two are "
        "independent settings that compose: when BOTH are restricted, only an "
        "address inside BOTH lists can reach the fleet remotely, and an "
        "address in neither is left with the physical/serial console. Whether "
        "a PARTICULAR address is admitted is not answered here — that depends "
        "on the source address of the request, which a chat client does not "
        "have; the Fleet screens compute it live."
    ),
    args_model=FindRemoteAccessDoorsArgs,
    category="admin",
    # Default enabled (NN #13) — read-only, no secrets, no off-prem calls,
    # and the composition it reports is the one thing neither existing tool
    # could show. module=None deliberately: find_web_ui_access is tagged
    # ``appliance.firewall``, so gating this the same way would hide the SSH
    # half too — exactly the blindness #1013 is about.
    default_enabled=True,
    module=None,
)
async def find_remote_access_doors(
    db: AsyncSession, user: User, args: FindRemoteAccessDoorsArgs
) -> dict[str, Any]:
    if (err := _superadmin_gate(user)) is not None:
        return err
    settings = await db.get(PlatformSettings, 1)
    # ``caller_ip=None`` is honest rather than a placeholder: there is no
    # request address here, so every ``admits`` below reflects only whether
    # the door is restricted at all.
    report = effective_doors(settings, None)
    web, ssh = report.web_ui, report.ssh
    if web.restricted and ssh.restricted:
        summary = (
            "Both remote doors are source-restricted — the Web UI to "
            f"{', '.join(web.allowed_cidrs)} and SSH to "
            f"{', '.join(ssh.allowed_cidrs)}. Only an address inside both "
            "lists can reach this fleet remotely; anything else is left with "
            "the appliance console."
        )
    elif web.restricted:
        summary = (
            f"The Web UI is restricted to {', '.join(web.allowed_cidrs)}; SSH "
            "is open from any source, so a wrong Web UI list stays recoverable."
        )
    elif ssh.restricted:
        summary = (
            f"SSH is restricted to {', '.join(ssh.allowed_cidrs)}; the Web UI "
            "is open from any source, so a wrong SSH list stays recoverable."
        )
    else:
        summary = "Neither remote door is source-restricted."
    return {
        "web_ui": {
            "restricted": web.restricted,
            "allowed_cidrs": list(web.allowed_cidrs),
        },
        "ssh": {
            "restricted": ssh.restricted,
            "allowed_cidrs": list(ssh.allowed_cidrs),
        },
        "both_restricted": web.restricted and ssh.restricted,
        "summary": summary,
    }
