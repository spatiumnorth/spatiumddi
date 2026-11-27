"""Git repository backup destination (issue #3211).

Each run commits the archive under a timestamped name and pushes it, so a
private repository on a Gitea / GitLab / GitHub the operator already runs
becomes versioned, off-site backup storage with the commit log as history.

Config shape:

* ``url`` — required. ``https://host/path.git``, ``ssh://user@host[:port]/path.git``
  or the scp-like ``user@host:path.git``. Never ``http://``, ``file://`` or
  ``ext::`` — the transport allow-list is enforced twice: here, and again in
  the environment handed to git (``GIT_ALLOW_PROTOCOL``).
* ``branch`` — default ``main``. Created (as a root commit) when the remote
  has no such branch, which is the empty-repository case.
* ``subdirectory`` — default ``backups``. Archives are written to
  ``<subdirectory>/<filename>``.
* ``username`` — HTTPS only, default ``git``. Most hosts ignore it for a
  token; some require a non-empty one.
* ``token`` — HTTPS auth. **Secret.** Sent as a ``Authorization: Basic``
  header handed to git through its environment, so it is on neither the
  command line nor in the stored clone.
* ``ssh_private_key`` — SSH auth, a deploy key with write access. **Secret.**
  Not passphrase-protected: git has nothing to type it into.
* ``known_hosts`` — required for an SSH URL. The host key is pinned to it
  (``StrictHostKeyChecking=yes``, no system or user known_hosts); there is
  deliberately no way to accept an unknown host key.
* ``max_archive_mb`` — default 95. An archive over it is refused before
  anything is pushed: GitHub rejects a file over 100 MB at push time, with a
  message about LFS that does not say which setting to change.

Implementation notes:

* The ``git`` binary is driven as a subprocess (``asyncio.to_thread``), one
  throwaway shallow clone per operation in a private temp dir, removed in a
  ``finally``. Nothing is cached between calls, so a rotated credential or
  host key applies on the next run.
* The history only grows. Archives are compressed and git cannot delta them,
  so retention here removes the file in a NEW commit — it frees nothing in the
  repository's history. The destination notice and the docs say so.
* Two workers pushing at once is handled: a rejected push is retried from a
  fresh fetch.
"""

from __future__ import annotations

import asyncio
import base64
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import structlog

from app.core.exc_text import describe_exc
from app.core.ssrf import SSRFBlockedError, assert_safe_target
from app.services.backup.targets.base import (
    ARCHIVE_NAME_RE,
    ArchiveListing,
    BackupDestination,
    BackupDestinationError,
    ConfigFieldSpec,
    DestinationConfigError,
    check_size,
    safe_filename,
    safe_url,
)
from app.services.backup.targets.scp import _pem_lost_its_line_breaks

logger = structlog.get_logger(__name__)

#: Operators may only name a network transport. Tests flip this to reach a
#: bare repository on disk, which no operator-facing config can.
_ALLOW_LOCAL_URLS = False

_GIT_TIMEOUT_S = 600
_PUSH_ATTEMPTS = 3
_DEFAULT_MAX_ARCHIVE_MB = 95
_SCP_LIKE_RE = re.compile(r"^[A-Za-z0-9._-]+@[A-Za-z0-9.\-]+:(?!//)[^\s]+$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_SUBDIR_PART_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_NAME_TS_RE = re.compile(r"(\d{8})-(\d{6})")
_AUTHOR = {
    "GIT_AUTHOR_NAME": "SpatiumDDI backup",
    "GIT_AUTHOR_EMAIL": "backup@spatiumddi.invalid",
    "GIT_COMMITTER_NAME": "SpatiumDDI backup",
    "GIT_COMMITTER_EMAIL": "backup@spatiumddi.invalid",
}


def _url_kind(url: str) -> str:
    """``https`` / ``ssh`` for a usable URL, ``file`` for a local path (tests
    only), else ``""``."""
    if url.startswith("-") or any(ord(c) < 0x21 for c in url):
        return ""
    low = url.lower()
    if low.startswith("https://"):
        return "https"
    if low.startswith("ssh://") or _SCP_LIKE_RE.match(url):
        return "ssh"
    if _ALLOW_LOCAL_URLS and (low.startswith("file://") or url.startswith("/")):
        return "file"
    return ""


def _branch(config: dict[str, Any]) -> str:
    return str(config.get("branch") or "main").strip()


def _subdir(config: dict[str, Any]) -> str:
    return str(config.get("subdirectory") or "backups").strip().strip("/")


def _max_bytes(config: dict[str, Any]) -> int:
    raw = config.get("max_archive_mb")
    mb = int(raw) if raw not in (None, "") else _DEFAULT_MAX_ARCHIVE_MB
    return mb * 1024 * 1024


@dataclass
class _Out:
    returncode: int
    stdout: Any  # str, or bytes when the call asked for ``raw``
    stderr: str


class _Run:
    """One working clone: its directory, its environment, and a way to run git."""

    def __init__(self, config: dict[str, Any], root: Path) -> None:
        self.config = config
        self.root = root
        self.work = root / "repo"
        self.work.mkdir()
        self.url = str(config["url"]).strip()
        self.kind = _url_kind(self.url)
        self._secrets: list[str] = [
            s for s in (config.get("token"), config.get("ssh_private_key")) if s
        ]
        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": str(root),
            "LANG": "C",
            "LC_ALL": "C",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_ALLOW_PROTOCOL": "https:ssh:file" if _ALLOW_LOCAL_URLS else "https:ssh",
            **_AUTHOR,
        }
        if self.kind == "https":
            user = str(config.get("username") or "git")
            basic = base64.b64encode(f"{user}:{config['token']}".encode()).decode()
            self._secrets.append(basic)
            env.update(
                GIT_CONFIG_COUNT="2",
                GIT_CONFIG_KEY_0="http.extraHeader",
                GIT_CONFIG_VALUE_0=f"Authorization: Basic {basic}",
                GIT_CONFIG_KEY_1="http.followRedirects",
                GIT_CONFIG_VALUE_1="false",
            )
        elif self.kind == "ssh":
            key = root / "id_key"
            fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(str(config["ssh_private_key"]).replace("\r\n", "\n").strip() + "\n")
            hosts = root / "known_hosts"
            hosts.write_text(str(config["known_hosts"]).strip() + "\n")
            env["GIT_SSH_COMMAND"] = " ".join(
                [
                    "ssh",
                    "-i",
                    shlex.quote(str(key)),
                    "-o IdentitiesOnly=yes",
                    "-o BatchMode=yes",
                    "-o StrictHostKeyChecking=yes",
                    f"-o UserKnownHostsFile={shlex.quote(str(hosts))}",
                    "-o GlobalKnownHostsFile=/dev/null",
                    "-o ConnectTimeout=30",
                ]
            )
        self.env = env

    def scrub(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, "<redacted>")
        text = text.replace(self.url, safe_url(self.url) if "://" in self.url else "<repository>")
        return text.strip()[:600]

    def git(self, *args: str, check: bool = True, raw: bool = False) -> _Out:
        try:
            proc = subprocess.run(  # noqa: S603 — argv list, no shell
                ["git", *args],
                cwd=self.work,
                env=self.env,
                capture_output=True,
                timeout=_GIT_TIMEOUT_S,
            )
        except FileNotFoundError as exc:
            raise BackupDestinationError("the git binary is not installed on this host") from exc
        except subprocess.TimeoutExpired as exc:
            raise BackupDestinationError(
                f"git {args[0]} timed out after {_GIT_TIMEOUT_S} s"
            ) from exc
        out = _Out(
            proc.returncode,
            proc.stdout if raw else proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"),
        )
        if check and out.returncode != 0:
            raise BackupDestinationError(f"git {args[0]} failed: {self.scrub(out.stderr)}")
        return out

    def fetch(self) -> bool:
        """Fresh shallow clone of the branch. False when the remote has no
        such branch (a new repository), which is not an error."""
        branch = _branch(self.config)
        self.git("init", "-q", f"--initial-branch={branch}")
        self.git("remote", "add", "origin", self.url)
        proc = self.git("fetch", "-q", "--depth", "1", "origin", branch, check=False)
        if proc.returncode == 0:
            self.git("checkout", "-q", "-B", branch, "FETCH_HEAD")
            return True
        if "couldn't find remote ref" in proc.stderr:
            return False
        raise BackupDestinationError(f"git fetch failed: {self.scrub(proc.stderr)}")

    def push(self, refspec: str) -> _Out:
        return self.git("push", "-q", "origin", refspec, check=False)

    def commit_and_push(self, message: str) -> None:
        branch = _branch(self.config)
        self.git("commit", "-q", "-m", message)
        proc = self.push(f"HEAD:refs/heads/{branch}")
        if proc.returncode != 0:
            raise _PushRejected(self.scrub(proc.stderr))


class _PushRejected(BackupDestinationError):
    """The push failed; the message is already scrubbed."""


@contextmanager
def _clone(config: dict[str, Any]) -> Iterator[_Run]:
    root = Path(tempfile.mkdtemp(prefix="spatium-git-"))
    try:
        yield _Run(config, root)
    finally:
        shutil.rmtree(root, ignore_errors=True)


class GitRepoDestination(BackupDestination):
    kind = "git"
    label = "Git repository"
    secret_alternatives = (("token",), ("ssh_private_key",))
    config_fields = (
        ConfigFieldSpec(
            name="_history_notice",
            label="History only grows",
            type="notice",
            required=False,
            description=(
                "Every backup adds its full size to the repository permanently: archives "
                "are compressed, so git cannot delta them. Retention removes old archives "
                "in a new commit, which frees nothing in history. The archive holds your "
                "whole database, so use a PRIVATE repository: pushed history cannot be "
                "recalled."
            ),
        ),
        ConfigFieldSpec(
            name="url",
            label="Repository URL",
            type="text",
            required=True,
            description=(
                "https://host/org/repo.git, ssh://git@host/org/repo.git or "
                "git@host:org/repo.git. The repository must already exist."
            ),
        ),
        ConfigFieldSpec(
            name="branch",
            label="Branch",
            type="text",
            required=False,
            description="Default main. Created on the first push if the repository is empty.",
        ),
        ConfigFieldSpec(
            name="subdirectory",
            label="Subdirectory",
            type="text",
            required=False,
            description="Where archives are written inside the repository. Default backups.",
        ),
        ConfigFieldSpec(
            name="username",
            label="Username (HTTPS)",
            type="text",
            required=False,
            description="HTTPS only. Default git; most hosts ignore it when a token is used.",
        ),
        ConfigFieldSpec(
            name="token",
            label="Access token (HTTPS)",
            type="password",
            required=False,
            secret=True,
            description="HTTPS URL: a token with write access. Set ONE of token / ssh_private_key.",
        ),
        ConfigFieldSpec(
            name="ssh_private_key",
            label="Deploy key (SSH, PEM)",
            type="password",
            multiline=True,
            required=False,
            secret=True,
            description=(
                "SSH URL: a private key with write access, without a passphrase. Paste the "
                "entire key including BEGIN / END lines."
            ),
        ),
        ConfigFieldSpec(
            name="known_hosts",
            label="known_hosts content",
            type="text",
            multiline=True,
            required=False,
            description=(
                "SSH URL: required. The server's host key line(s), e.g. the output of "
                "`ssh-keyscan <host>` checked against the host's published fingerprint. "
                "An unknown host key is always refused."
            ),
        ),
        ConfigFieldSpec(
            name="max_archive_mb",
            label="Largest archive (MB)",
            type="text",
            required=False,
            description=(
                "Default 95. A larger archive is refused before it is pushed. GitHub rejects "
                "files over 100 MB and Git LFS is not supported; raise this for a self-hosted "
                "server whose limit you control."
            ),
        ),
    )

    def unused_secret_fields(self, config: dict[str, Any]) -> frozenset[str]:
        kind = _url_kind(str(config.get("url") or "").strip())
        if kind == "https":
            return frozenset({"ssh_private_key"})
        if kind == "ssh":
            return frozenset({"token"})
        return frozenset()

    def validate_config(self, config: dict[str, Any]) -> None:
        url = config.get("url")
        if not url or not isinstance(url, str) or not url.strip():
            raise DestinationConfigError("'url' is required and must be a non-empty string")
        url = url.strip()
        kind = _url_kind(url)
        if not kind:
            raise DestinationConfigError(
                "'url' must be https://…, ssh://… or user@host:path (http://, file:// and "
                "other transports are refused)"
            )
        if kind == "https":
            parts = urlsplit(url)
            if parts.username or parts.password:
                raise DestinationConfigError(
                    "'url' must not carry credentials: put the token in 'token'"
                )
            if not parts.hostname:
                raise DestinationConfigError("'url' has no host")
        branch = _branch(config)
        if (
            not _BRANCH_RE.match(branch)
            or ".." in branch
            or "//" in branch
            or branch.endswith(("/", ".", ".lock"))
        ):
            raise DestinationConfigError(f"'branch' {branch!r} is not a valid branch name")
        sub = _subdir(config)
        if not sub or any(not _SUBDIR_PART_RE.match(p) or p == ".git" for p in sub.split("/")):
            raise DestinationConfigError(
                "'subdirectory' must be a relative path of plain names (no '..', no '.git')"
            )
        raw = config.get("max_archive_mb")
        if raw not in (None, ""):
            try:
                mb = int(raw)
            except (TypeError, ValueError):
                raise DestinationConfigError("'max_archive_mb' must be a whole number") from None
            if mb < 1:
                raise DestinationConfigError("'max_archive_mb' must be at least 1")
        if kind == "https":
            if not config.get("token"):
                raise DestinationConfigError("'token' is required for an https URL")
        elif kind == "ssh":
            key = config.get("ssh_private_key")
            if not key or not isinstance(key, str):
                raise DestinationConfigError("'ssh_private_key' is required for an SSH URL")
            if _pem_lost_its_line_breaks(key):
                raise DestinationConfigError(
                    "'ssh_private_key' has lost its line breaks: the BEGIN line, body and END "
                    "line must each be on their own line"
                )
            if not str(config.get("known_hosts") or "").strip():
                raise DestinationConfigError(
                    "'known_hosts' is required for an SSH URL — paste the server's host key "
                    "line(s) (e.g. the output of `ssh-keyscan <host>`); an unknown host key "
                    "is never accepted"
                )

    async def validate_config_network(self, config: dict[str, Any]) -> None:
        url = str(config.get("url") or "").strip()
        kind = _url_kind(url)
        if kind not in ("https", "ssh"):
            return
        target = url
        if _SCP_LIKE_RE.match(url):
            target = "ssh://" + url.split("@", 1)[1].split(":", 1)[0]
        try:
            await asyncio.to_thread(assert_safe_target, target, label="backup_git", block=True)
        except SSRFBlockedError as exc:
            raise DestinationConfigError(f"refusing this URL: {exc}") from exc

    # ── operations ────────────────────────────────────────────────────

    def _path(self, config: dict[str, Any], filename: str) -> str:
        return f"{_subdir(config)}/{safe_filename(filename)}"

    async def write(self, *, config: dict[str, Any], filename: str, archive_bytes: bytes) -> None:
        path = self._path(config, filename)
        cap = _max_bytes(config)
        if len(archive_bytes) > cap:
            raise BackupDestinationError(
                f"archive is {len(archive_bytes)} bytes, over this destination's "
                f"{cap}-byte limit ('max_archive_mb'); a git host would reject it at push "
                "time. Raise the limit if your server allows larger files."
            )

        def _do() -> None:
            last = ""
            for _ in range(_PUSH_ATTEMPTS):
                with _clone(config) as run:
                    run.fetch()
                    target = run.work / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(archive_bytes)
                    run.git("add", "--", path)
                    try:
                        run.commit_and_push(f"Backup {safe_filename(filename)}")
                    except _PushRejected as exc:
                        last = str(exc)
                        continue
                    return
            raise BackupDestinationError(f"git push failed: {last}")

        await asyncio.to_thread(_do)

    def _listing(self, run: _Run, config: dict[str, Any]) -> list[ArchiveListing]:
        sub = _subdir(config)
        proc = run.git("ls-tree", "-l", "-z", "HEAD", f"{sub}/", raw=True)
        head_time = datetime.fromtimestamp(
            int(run.git("log", "-1", "--format=%ct").stdout.strip() or 0), UTC
        )
        rows: list[ArchiveListing] = []
        for entry in proc.stdout.split(b"\0"):
            if not entry:
                continue
            meta, _, path = entry.decode("utf-8", "replace").partition("\t")
            fields = meta.split()
            if len(fields) < 4 or fields[1] != "blob":
                continue
            name = path.rsplit("/", 1)[-1]
            if not ARCHIVE_NAME_RE.match(name):
                continue
            created = head_time
            m = _NAME_TS_RE.search(name)
            if m:
                try:
                    created = datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S").replace(
                        tzinfo=UTC
                    )
                except ValueError:
                    pass
            rows.append(
                ArchiveListing(filename=name, size_bytes=int(fields[3]), created_at=created)
            )
        rows.sort(key=lambda r: r.created_at, reverse=True)
        return rows

    async def list_archives(self, *, config: dict[str, Any]) -> list[ArchiveListing]:
        def _do() -> list[ArchiveListing]:
            with _clone(config) as run:
                if not run.fetch():
                    return []
                return self._listing(run, config)

        return await asyncio.to_thread(_do)

    async def download(
        self, *, config: dict[str, Any], filename: str, max_bytes: int | None = None
    ) -> bytes:
        from app.services.backup.targets.base import ArchiveNotFoundError  # noqa: PLC0415

        path = self._path(config, filename)

        def _do() -> bytes:
            with _clone(config) as run:
                if not run.fetch():
                    raise ArchiveNotFoundError(f"archive {filename!r} not found in repository")
                size = run.git("cat-file", "-s", f"HEAD:{path}", check=False)
                if size.returncode != 0:
                    raise ArchiveNotFoundError(f"archive {filename!r} not found at {path}")
                check_size(filename, int(size.stdout.strip()), max_bytes)
                return bytes(run.git("cat-file", "blob", f"HEAD:{path}", raw=True).stdout)

        return await asyncio.to_thread(_do)

    async def delete(self, *, config: dict[str, Any], filename: str) -> None:
        path = self._path(config, filename)

        def _do() -> None:
            last = ""
            for _ in range(_PUSH_ATTEMPTS):
                with _clone(config) as run:
                    if not run.fetch() or not (run.work / path).is_file():
                        return  # idempotent
                    run.git("rm", "-q", "--", path)
                    try:
                        run.commit_and_push(f"Prune {safe_filename(filename)}")
                    except _PushRejected as exc:
                        last = str(exc)
                        continue
                    return
            raise BackupDestinationError(f"git push failed: {last}")

        await asyncio.to_thread(_do)

    async def test_connection(self, *, config: dict[str, Any]) -> dict[str, Any]:
        try:
            self.validate_config(config)
            await self.validate_config_network(config)
        except DestinationConfigError as exc:
            return {"ok": False, "error": str(exc)}

        scratch = f"spatiumddi-test-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"

        def _do() -> dict[str, Any]:
            try:
                with _clone(config) as run:
                    existed = run.fetch()
                    # A real push, to a scratch branch, so a read-only token or
                    # deploy key fails here and not on the first nightly run.
                    run.git("commit", "-q", "--allow-empty", "-m", "SpatiumDDI connection test")
                    proc = run.push(f"HEAD:refs/heads/{scratch}")
                    if proc.returncode != 0:
                        return {
                            "ok": False,
                            "error": f"push to a scratch branch failed: {run.scrub(proc.stderr)}",
                        }
                    cleanup = run.push(f":refs/heads/{scratch}")
            except BackupDestinationError as exc:
                return {"ok": False, "error": str(exc)}
            except Exception as exc:  # noqa: BLE001
                return {"ok": False, "error": describe_exc(exc)}
            branch = _branch(config)
            where = (
                f"branch {branch!r}"
                if existed
                else f"empty repository (branch {branch!r} will be created)"
            )
            detail = f"fetched {where}, pushed a scratch branch and deleted it"
            if cleanup.returncode != 0:
                detail = (
                    f"fetched {where} and pushed scratch branch {scratch!r}, but could not "
                    "delete it — remove it on the server"
                )
            return {"ok": True, "detail": detail}

        return await asyncio.to_thread(_do)
