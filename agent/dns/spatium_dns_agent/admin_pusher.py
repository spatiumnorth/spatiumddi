"""Admin runtime-state pushers — rendered-config snapshot + rndc status.

Two operator-diagnostics pieces ship from here, both keyed off the
new ``/api/v1/dns/agents/admin/*`` endpoints:

- ``push_rendered_config(...)`` is called by the sync loop right after
  a successful structural apply. It walks the on-disk rendered tree
  (``state_dir/rendered/``) and POSTs every file's relative path +
  text content. The control plane keeps the most-recent snapshot per
  server in ``dns_server_runtime_state.rendered_files`` so operators
  can answer "is the server actually running the config we sent?"
  without SSHing in.
- ``RndcStatusPoller`` is a long-lived thread that shells out to
  ``rndc status`` once a minute, capturing stdout, and POSTs the text
  to ``/admin/rndc-status``. The Overview tab on the Server Detail
  modal renders the latest snapshot.

Both pushes are best-effort: the agent's primary loop never blocks on
them, and a transient 5xx just gets retried on the next tick.
"""

from __future__ import annotations

import random
import re
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Iterable

import httpx
import structlog

from .config import AgentConfig

log = structlog.get_logger(__name__)

# Skip files that the agent writes alongside the rendered tree but
# aren't meaningful for the operator (binary state, locks, etc).
_SKIP_FILE_NAMES: frozenset[str] = frozenset()
_RENDERED_DIR_NAME = "rendered"

_REDACTED = "***REDACTED***"

# Credentials that appear INSIDE rendered config, which this module uploads
# to the control plane (#869). Making the files 0600 on disk protects them
# from other uids on the appliance and does nothing about this path — the
# snapshot is stored server-side and served back over the API, so an
# unredacted push puts the pdns REST api-key and the TSIG secrets that
# authorise dynamic updates into the database and onto any screen allowed to
# read them. The PowerDNS driver's own comment asserts these "never leave the
# appliance"; that is only true with this redaction in place.
#
# Regex rather than a JSON/config parse on purpose: this runs over whatever
# a driver happens to have rendered, and a parse failure must not be the
# thing standing between a secret and the wire. A pattern that over-matches
# costs an operator some debugging context; one that under-matches leaks a
# credential.
_REDACTIONS: tuple[re.Pattern[str], ...] = (
    # pdns.conf: ``api-key=<value>`` (also covers any ``*-key=`` setting).
    re.compile(r"(?im)^([ \t]*[\w.-]*api-key[ \t]*=[ \t]*).+$"),
    # zones.json: ``"secret": "<value>"`` anywhere in the tree.
    re.compile(r'(?i)("secret"[ \t]*:[ \t]*")[^"]*(")'),
    # BIND-style ``secret "<value>";`` — nothing renders this into the
    # pushed tree today (named.conf includes the key file rather than
    # inlining it), which is exactly why it is cheap to guard now.
    re.compile(r'(?i)(\bsecret[ \t]+")[^"]*(")'),
)


def redact_secrets(content: str) -> str:
    """Mask credential values in a rendered-config file before upload.

    Values only — the surrounding key/setting name is preserved so the
    operator can still see THAT an api-key or TSIG secret is configured,
    which is usually the question they opened the snapshot to answer.
    """
    for pattern in _REDACTIONS:
        if pattern.groups == 2:
            content = pattern.sub(rf"\1{_REDACTED}\2", content)
        else:
            content = pattern.sub(rf"\1{_REDACTED}", content)
    return content


def _cp_client(cfg: AgentConfig) -> httpx.Client:
    verify = cfg.httpx_verify()
    return httpx.Client(base_url=cfg.control_plane_url, verify=verify, timeout=15.0)


def _walk_rendered(rendered_dir: Path) -> Iterable[tuple[str, str]]:
    """Yield ``(relpath, content)`` pairs for every text file in the tree.

    Binary files (TSIG keyrings, etc) and anything we can't decode as
    UTF-8 are skipped — the operator-facing UI only renders text.
    """
    if not rendered_dir.is_dir():
        return
    for path in sorted(rendered_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name in _SKIP_FILE_NAMES:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        rel = path.relative_to(rendered_dir).as_posix()
        # Redact on the way OUT of the appliance, not at the call site — this
        # generator is the single chokepoint every pushed file passes through,
        # so a future caller can't accidentally bypass it (#869).
        yield rel, redact_secrets(content)


def push_rendered_config(cfg: AgentConfig, token: str) -> None:
    """One-shot push of every text file under ``state_dir/rendered/``."""
    rendered = cfg.state_dir / _RENDERED_DIR_NAME
    files = [{"path": rel, "content": content} for rel, content in _walk_rendered(rendered)]
    if not files:
        log.debug("rendered_config_push_skipped", reason="no_files")
        return
    try:
        with _cp_client(cfg) as c:
            resp = c.post(
                "/api/v1/dns/agents/admin/rendered-config",
                json={"files": files},
                headers={"Authorization": f"Bearer {token}"},
            )
        if resp.status_code not in (200, 204):
            log.warning("rendered_config_push_non200", status=resp.status_code)
    except httpx.HTTPError as e:
        log.warning("rendered_config_push_http_error", error=str(e))


class RndcStatusPoller:
    """Periodic ``rndc status`` capture + push.

    Cadence is 60 s with ±3 s jitter, matching the metrics poller. We
    don't push when ``rndc`` isn't on PATH (agent might be running
    against a non-BIND9 driver in the future) or when the command
    fails — the operator-facing UI will simply show "no snapshot yet"
    in that case.
    """

    def __init__(self, cfg: AgentConfig, token_ref: list[str]):
        self.cfg = cfg
        self.token_ref = token_ref
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def _capture(self) -> str | None:
        if not shutil.which("rndc"):
            return None
        # Prefer the agent-owned rndc.conf the entrypoint writes — the
        # system /etc/bind/rndc.key is mode 600 inside a restricted dir
        # so the agent user can't read it directly. The conf wraps the
        # key + supplies default-server so plain `rndc status` works.
        cmd = ["rndc"]
        agent_conf = self.cfg.state_dir / "rndc.conf"
        if agent_conf.exists():
            cmd += ["-c", str(agent_conf)]
        cmd.append("status")
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=10.0,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            log.debug("rndc_status_capture_failed", error=str(e))
            return None
        if res.returncode != 0:
            return f"rndc status exited {res.returncode}\n{res.stderr.strip()}"
        return res.stdout

    def _report(self, text: str) -> None:
        try:
            with _cp_client(self.cfg) as c:
                resp = c.post(
                    "/api/v1/dns/agents/admin/rndc-status",
                    json={"text": text},
                    headers={"Authorization": f"Bearer {self.token_ref[0]}"},
                )
            if resp.status_code not in (200, 204):
                log.warning("rndc_status_push_non200", status=resp.status_code)
        except httpx.HTTPError as e:
            log.warning("rndc_status_push_http_error", error=str(e))

    def run(self) -> None:
        while not self._stop.is_set():
            text = self._capture()
            if text is not None:
                self._report(text)
            interval = 60.0 + random.uniform(-3, 3)
            self._stop.wait(timeout=max(30.0, interval))


__all__ = ["RndcStatusPoller", "push_rendered_config"]
