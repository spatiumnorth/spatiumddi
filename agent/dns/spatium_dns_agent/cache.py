"""On-disk cache for the agent (non-negotiable #5).

Layout under /var/lib/spatium-dns-agent/:
    agent-id                       # UUID, 0600
    agent_token.jwt                # current JWT, 0600
    config/current.json            # last bundle FETCHED from the control plane
    config/current.etag
    config/previous.json           # last bundle that APPLIED cleanly (#882)
    config/previous.etag
    config/quarantine.json         # etag of a bundle that failed to apply (#882)
    rendered/                      # managed by driver
    ops/{inflight,failed}/
"""

from __future__ import annotations

import json
import os
import shutil
import uuid
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)


def ensure_layout(state_dir: Path) -> None:
    for sub in ("config", "rendered", "tsig", "ops/inflight", "ops/failed"):
        (state_dir / sub).mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, 0o700)


def load_or_create_agent_id(state_dir: Path) -> str:
    path = state_dir / "agent-id"
    if path.exists():
        return path.read_text().strip()
    aid = str(uuid.uuid4())
    path.write_text(aid)
    os.chmod(path, 0o600)
    return aid


def load_token(state_dir: Path) -> str | None:
    path = state_dir / "agent_token.jwt"
    if not path.exists():
        return None
    return path.read_text().strip()


def save_token(state_dir: Path, token: str) -> None:
    path = state_dir / "agent_token.jwt"
    tmp = path.with_suffix(".jwt.tmp")
    tmp.write_text(token)
    os.chmod(tmp, 0o600)
    tmp.replace(path)


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
    every fetch did ``current.replace(previous)`` before the apply had been
    attempted, which made ``previous`` mean "the bundle before this one"
    rather than "the last one that worked". Those are the same thing only
    while every apply succeeds — and the case this cache exists for is the
    one where an apply does not.

    Concretely, the old rotation destroyed the fallback in two poll cycles:
    a bundle that fails to apply leaves ``_current_etag`` unadvanced, so the
    next poll re-fetches the SAME bad bundle and rotates it — now bad — into
    ``previous``, overwriting the last config known to work.

    ``previous`` is now written by :func:`commit_config`, which the sync loop
    calls only after the driver has accepted the bundle.
    """
    cfg_dir = state_dir / "config"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    current = cfg_dir / "current.json"
    tmp = cfg_dir / "current.json.tmp"
    # Stream into the file (#1705): ``json.dumps`` built the whole bundle as
    # one string and ``write_text`` encoded it again, two extra copies of a
    # config that is >100 MB with a catalog-sized blocklist. Compact, too — a
    # cache file nobody reads by eye does not need ``indent=2``. ``sort_keys``
    # stays so the bytes are stable for a given bundle.
    # Durable before visible: the rename only happens once every byte is on
    # disk, so neither a crash mid-dump nor a power cut after the rename can
    # leave ``current.json`` truncated — and a truncated cache is no cache,
    # since ``load_config`` reads a JSON error as "nothing cached"
    # (non-negotiable #5).
    try:
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(bundle, fh, sort_keys=True, separators=(",", ":"))
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    tmp.replace(current)
    (cfg_dir / "current.etag").write_text(etag)


def commit_config(state_dir: Path, etag: str) -> None:
    """Promote ``current`` to ``previous`` — the last-known-GOOD bundle (#882).

    Call this only once the driver has rendered, validated and reloaded the
    bundle successfully. ``previous.json`` is what
    :func:`load_previous_config` hands back when a later bundle has to be
    reverted, so anything that lands here must be known to work.

    Copies rather than renames: ``current`` has to stay in place, because it
    is what the agent re-applies on restart.
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
    # ``copyfile`` streams in kernel-sized chunks (#1705); ``read_text`` then
    # ``write_text`` held the file decoded and re-encoded in memory.
    shutil.copyfile(current, tmp)
    # fsync before the rename for the same reason as ``save_config``: this is
    # the revert fallback, and a truncated one is worse than a stale one.
    with tmp.open("rb") as fh:
        os.fsync(fh.fileno())
    tmp.replace(cfg_dir / "previous.json")
    etag_tmp = cfg_dir / "previous.etag.tmp"
    etag_tmp.write_text(etag_path.read_text())
    etag_tmp.replace(cfg_dir / "previous.etag")


def load_previous_config(state_dir: Path) -> tuple[dict[str, Any] | None, str | None]:
    """The last bundle that applied cleanly, for the revert path (#882).

    ``(None, None)`` when there is nothing to fall back to — a brand-new
    agent whose very first bundle is the broken one. The caller has to
    report that case distinctly (``no_previous``): there is no safe state to
    return to, so the operator has to fix the config rather than wait.

    Note the etag may be absent even when the bundle is present: agents
    upgraded in the field carry a ``previous.json`` written by the old
    rotating :func:`save_config`, which never wrote ``previous.etag``. The
    bundle is still a usable fallback, so a missing etag is not a rejection.
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
