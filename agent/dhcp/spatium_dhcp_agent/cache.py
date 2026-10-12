"""On-disk cache for the DHCP agent (non-negotiable #5).

Layout under /var/lib/spatium-dhcp-agent/:
    agent-id                        # UUID, 0600
    agent_token.jwt                 # current JWT, 0600
    config/current.json             # last bundle FETCHED from the control plane
    config/current.etag
    config/previous.json            # last bundle that APPLIED cleanly (#882)
    config/previous.etag
    config/quarantine.json          # etag of a bundle that failed to apply (#882)
    rendered/kea-dhcp4.json         # rendered Kea config (last applied)
    leases/pending.jsonl            # lease events not yet posted to the control plane
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)

# Schema version for the cached ConfigBundle — see DHCP.md §6.
CACHE_SCHEMA_VERSION = 1


def ensure_layout(state_dir: Path) -> None:
    for sub in ("config", "rendered", "leases"):
        (state_dir / sub).mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(state_dir, 0o700)
    except PermissionError:
        # Volume-mount owner may differ; best-effort only.
        pass


def load_or_create_agent_id(state_dir: Path) -> str:
    path = state_dir / "agent-id"
    if path.exists():
        return path.read_text().strip()
    aid = str(uuid.uuid4())
    path.write_text(aid)
    try:
        os.chmod(path, 0o600)
    except PermissionError:
        pass
    return aid


def load_token(state_dir: Path) -> str | None:
    path = state_dir / "agent_token.jwt"
    if not path.exists():
        return None
    tok = path.read_text().strip()
    return tok or None


def save_token(state_dir: Path, token: str) -> None:
    path = state_dir / "agent_token.jwt"
    tmp = path.with_suffix(".jwt.tmp")
    tmp.write_text(token)
    try:
        os.chmod(tmp, 0o600)
    except (PermissionError, FileNotFoundError):
        pass
    try:
        tmp.replace(path)
    except FileNotFoundError:
        # Another thread already moved our tmp (concurrent save_token).
        pass


def load_config(state_dir: Path) -> tuple[dict[str, Any] | None, str | None]:
    cfg_path = state_dir / "config" / "current.json"
    etag_path = state_dir / "config" / "current.etag"
    if not cfg_path.exists():
        return None, None
    try:
        cfg = json.loads(cfg_path.read_text())
    except json.JSONDecodeError:
        return None, None
    etag = etag_path.read_text().strip() if etag_path.exists() else None
    return cfg, etag


def save_config(state_dir: Path, bundle: dict[str, Any], etag: str) -> None:
    """Persist the bundle we just FETCHED as ``current`` (atomic rename).

    Deliberately does **not** touch ``previous.json`` (#882). It used to:
    every fetch rotated current→previous before the apply had been
    attempted, which made ``previous`` mean "the bundle before this one"
    rather than "the last one that worked" — the same thing only while
    every apply succeeds, which is exactly the case this cache is not for.

    ``previous`` is now written by :func:`commit_config`, once Kea has
    accepted the rendered config.
    """
    cfg_dir = state_dir / "config"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    current = cfg_dir / "current.json"
    tmp = cfg_dir / "current.json.tmp"
    # Stamp the schema version so older/newer agents can detect incompatible caches.
    stamped = dict(bundle)
    stamped.setdefault("_schema_version", CACHE_SCHEMA_VERSION)
    tmp.write_text(json.dumps(stamped, indent=2, sort_keys=True))
    tmp.replace(current)
    (cfg_dir / "current.etag").write_text(etag)


def commit_config(state_dir: Path, etag: str) -> None:
    """Promote ``current`` to ``previous`` — the last-known-GOOD bundle (#882).

    Called only after the ``-t`` preflight and ``config-reload`` both
    succeeded, so whatever lands here is known to load.

    Copies rather than renames: ``current`` stays in place because it is
    what the agent re-applies on restart.
    """
    cfg_dir = state_dir / "config"
    current = cfg_dir / "current.json"
    etag_path = cfg_dir / "current.etag"
    if not current.exists() or not etag_path.exists():
        return
    # Guard the precondition rather than assume it. Promoting ``current``
    # is only correct while ``current`` IS the bundle that just applied;
    # a caller that applied something else (a revert, a bundle read from
    # elsewhere) would otherwise silently stamp the wrong config as
    # last-known-good, which is the one thing this file must never hold.
    if etag_path.read_text().strip() != etag:
        log.warning(
            "commit_config_etag_mismatch",
            applied_etag=etag,
            cached_etag=etag_path.read_text().strip(),
        )
        return
    if (cfg_dir / "previous.etag").exists():
        # Already committed — skip the copy. ``commit_config`` is called from
        # more than one point in a successful poll (the structural-apply path
        # and the end-of-poll confirmation), and this bundle can be tens of
        # kilobytes.
        try:
            if (cfg_dir / "previous.etag").read_text().strip() == etag:
                return
        except OSError:
            pass  # unreadable sidecar → fall through and rewrite it
    tmp = cfg_dir / "previous.json.tmp"
    # Copy the bytes rather than re-serialise the bundle: ``previous.json``
    # has to be exactly what ``current.json`` was, because that is what the
    # agent replays on a revert. Two independent serialisations could drift.
    tmp.write_text(current.read_text())
    tmp.replace(cfg_dir / "previous.json")
    etag_tmp = cfg_dir / "previous.etag.tmp"
    etag_tmp.write_text(etag_path.read_text())
    etag_tmp.replace(cfg_dir / "previous.etag")


def load_previous_config(state_dir: Path) -> tuple[dict[str, Any] | None, str | None]:
    """The last bundle Kea accepted, for the revert path (#882).

    ``(None, None)`` when there is nothing to fall back to — a new agent
    whose first bundle is the broken one. The caller reports that case
    distinctly (``no_previous``): there is no safe state to return to.

    The etag may be absent even when the bundle is present: agents upgraded
    in the field carry a ``previous.json`` written by the old rotating
    :func:`save_config`, which never wrote ``previous.etag``. That bundle is
    still a usable fallback, so a missing etag is not a rejection.
    """
    cfg_dir = state_dir / "config"
    cfg_path = cfg_dir / "previous.json"
    if not cfg_path.exists():
        return None, None
    try:
        cfg = json.loads(cfg_path.read_text())
    except json.JSONDecodeError:
        return None, None
    etag_path = cfg_dir / "previous.etag"
    etag = etag_path.read_text().strip() if etag_path.exists() else None
    return cfg, etag


def save_rendered_kea(state_dir: Path, rendered: dict[str, Any]) -> Path:
    """Write the rendered Kea dhcp4 JSON under rendered/ for audit/debug."""
    path = state_dir / "rendered" / "kea-dhcp4.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(rendered, indent=2, sort_keys=True))
    tmp.replace(path)
    return path
