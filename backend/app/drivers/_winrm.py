"""Shared WinRM / PowerShell execution chokepoint for the Windows drivers.

The Windows DNS and DHCP drivers both shell PowerShell to a Windows host
over WinRM (pywinrm). This module is the single place that builds the
session, picks transport/TLS, enforces timeouts, and — critically —
guards the ``powershell -EncodedCommand`` size limit so a large batch
fails *loudly and early* instead of silently overflowing the CMD.EXE
command-line cap and hard-failing an entire chunk (#426).

``run_ps`` is blocking — call it via ``asyncio.to_thread``.
"""

from __future__ import annotations

import base64
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# pywinrm dispatches PowerShell as ``powershell.exe -EncodedCommand <b64>``
# wrapped by CMD.EXE (``skip_cmd_shell=False``), so the whole command line
# is bound by CMD's ~8191-char limit. The encoded command is
# ``base64(utf-16-le(script))`` ≈ 2.67× the script's character count. We
# budget conservatively, leaving headroom for the ``powershell.exe
# -EncodedCommand `` prefix + CMD quoting. Dispatchers pack batches under
# this via ``encoded_command_len``.
MAX_ENCODED_COMMAND = 7800

# Timeouts: read_timeout must be strictly greater than operation_timeout
# (pywinrm asserts this). Without them a wedged call retries the
# output-receive indefinitely and ties up a worker thread forever (#426).
_OPERATION_TIMEOUT_SEC = 120
_READ_TIMEOUT_SEC = 150


class WinRMCommandTooLong(RuntimeError):
    """The encoded PowerShell command exceeds the CMD.EXE line budget.

    Raised before dispatch so the caller can split the batch rather than
    let CMD.EXE truncate it into a cryptic parser error.
    """


def encoded_command_len(script: str) -> int:
    """Length of the base64 ``-EncodedCommand`` payload pywinrm would
    send for ``script`` (UTF-16-LE → base64). Dispatchers use this to
    pack a batch under ``MAX_ENCODED_COMMAND``."""
    return len(base64.b64encode(script.encode("utf-16-le")))


# The WinRM transports this build can actually speak (#1128). pywinrm names
# more — ``kerberos`` among them — but Kerberos needs the ``gssapi`` package
# and the system Kerberos libraries, which have no Linux wheel and are not in
# the images, plus realm / KDC configuration the control plane has nowhere to
# take from. It was offered anyway and failed on every call, so it is not
# offered at all now. Real Kerberos support is tracked in #1128.
SUPPORTED_TRANSPORTS: tuple[str, ...] = ("ntlm", "credssp", "basic")

KERBEROS_UNSUPPORTED = (
    "The kerberos WinRM transport is not supported: the images carry no Kerberos "
    "(GSSAPI) libraries, so it has never been able to connect. Use ntlm, or credssp "
    "where the server has to reach another one (Windows DHCP failover management). "
    "Kerberos support is tracked in issue #1128."
)


def validate_transport(value: str | None) -> str | None:
    """Pydantic field-validator body shared by the DNS and DHCP credential
    inputs: refuse a transport this build cannot speak, at save rather than at
    the first call."""
    if value is None:
        return None
    if value == "kerberos":
        raise ValueError(KERBEROS_UNSUPPORTED)
    if value not in SUPPORTED_TRANSPORTS:
        raise ValueError(f"transport must be one of {', '.join(SUPPORTED_TRANSPORTS)}")
    return value


# The non-secret connection settings of a stored WinRM credential blob. The
# server responses echo these (never ``username`` / ``password``) so an edit
# dialog can show what is stored instead of a hard-coded default.
WINRM_SETTING_KEYS: tuple[str, ...] = ("winrm_port", "transport", "use_tls", "verify_tls")


def effective_winrm_settings(creds: dict[str, Any]) -> dict[str, Any]:
    """The connection settings ``run_ps`` will actually use for ``creds``.

    One reading for the session builder and the API echo, so what an edit
    dialog shows is what the next WinRM call does — including for a blob
    stored without one of the keys.
    """
    use_tls = bool(creds.get("use_tls", False))
    return {
        "winrm_port": int(creds.get("winrm_port") or (5986 if use_tls else 5985)),
        "transport": creds.get("transport") or "ntlm",
        "use_tls": use_tls,
        "verify_tls": bool(creds.get("verify_tls", False)),
    }


def winrm_settings_diff(
    before: dict[str, Any] | None, after: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    """``{key: {"old": …, "new": …}}`` for each effective setting that moved.

    For the audit row: a credential update records the old and new value of
    every non-secret setting it changed, not just the key names it carried.
    ``before`` is None when nothing was stored.
    """
    new = effective_winrm_settings(after)
    old = effective_winrm_settings(before) if before is not None else None
    return {
        k: {"old": old[k] if old is not None else None, "new": new[k]}
        for k in WINRM_SETTING_KEYS
        if old is None or old[k] != new[k]
    }


def _warn_insecure_transport(host: str, transport: str, use_tls: bool, verify_tls: bool) -> None:
    """Emit a one-time-ish WARNING when the WinRM transport is insecure,
    matching the #289 hardening on the proxmox / unifi / opnsense / ftp
    clients (which previously logged nothing about disabled TLS)."""
    if use_tls and not verify_tls:
        logger.warning(
            "winrm_tls_verification_disabled",
            host=host,
            hint=(
                "WinRM over HTTPS with certificate validation OFF "
                "(verify_tls=false) — set verify_tls and install the host "
                "cert to authenticate the server."
            ),
        )
    if not use_tls and transport == "basic":
        logger.warning(
            "winrm_cleartext_basic_auth",
            host=host,
            hint=(
                "WinRM basic auth over plain HTTP ships the password "
                "effectively in cleartext — use ntlm or enable TLS."
            ),
        )


def run_ps(
    host: str,
    creds: dict[str, Any],
    script: str,
    *,
    op_label: str = "winrm",
) -> str:
    """Run a PowerShell script on a Windows host over WinRM.

    Blocking — call via ``asyncio.to_thread``. Returns stdout as text.
    Raises :class:`WinRMCommandTooLong` if the encoded command would
    overflow the CMD.EXE budget (split the batch and retry), or
    ``RuntimeError`` on a non-zero exit / WinRM transport error.
    """
    # Guard the size BEFORE building a session so an oversized batch is a
    # clear, catchable error rather than a truncated-command failure.
    enc_len = encoded_command_len(script)
    if enc_len > MAX_ENCODED_COMMAND:
        raise WinRMCommandTooLong(
            f"{op_label}: encoded PowerShell command is {enc_len} chars, over the "
            f"{MAX_ENCODED_COMMAND} CMD.EXE budget — split the batch into smaller chunks"
        )

    # Deferred import: keeps celery-worker startup light and means hosts
    # that only run agent-based drivers don't need the pywinrm wheel.
    import winrm  # noqa: PLC0415

    settings = effective_winrm_settings(creds)
    transport = settings["transport"]
    if transport == "kerberos":
        # A server saved with Kerberos before #1128 — say why, instead of
        # letting pywinrm fail on the missing library.
        raise RuntimeError(KERBEROS_UNSUPPORTED + " Edit the server and pick another transport.")
    use_tls = settings["use_tls"]
    verify_tls = settings["verify_tls"]
    port = settings["winrm_port"]
    scheme = "https" if use_tls else "http"
    endpoint = f"{scheme}://{host}:{port}/wsman"

    _warn_insecure_transport(host, transport, use_tls, verify_tls)

    session = winrm.Session(
        endpoint,
        auth=(creds.get("username", ""), creds.get("password", "")),
        transport=transport,
        server_cert_validation="validate" if verify_tls else "ignore",
        operation_timeout_sec=_OPERATION_TIMEOUT_SEC,
        read_timeout_sec=_READ_TIMEOUT_SEC,
    )
    result = session.run_ps(script)
    stdout = (result.std_out or b"").decode("utf-8", errors="replace")
    stderr = (result.std_err or b"").decode("utf-8", errors="replace")
    if result.status_code != 0:
        raise RuntimeError(
            f"winrm exit={result.status_code}: "
            f"{stderr.strip() or stdout.strip() or '<no output>'}"
        )
    return stdout
