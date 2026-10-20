"""On-disk cache for the agent (non-negotiable #5).

Layout under /var/lib/spatium-dns-agent/:
    agent-id                       # UUID, 0600
    agent_token.jwt                # current JWT, 0600
    config/current.json            # last bundle FETCHED from the control plane
    config/current.etag
    config/previous.json           # last bundle that APPLIED cleanly (#882)
    config/previous.etag
    config/quarantine.json         # etag of a bundle that failed to apply (#882)
    config/apply_guard.json        # bundle being applied/settling + deaths (#2019)
    config/held.json               # the bundle a startup hold set aside (#2223)
    rendered/                      # managed by driver
    ops/{inflight,failed}/

A 200's body is spooled to ``config/fetch.json.part`` while it downloads
(#2029). It is never read as a cache and is removed on start.
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


# Where a config reply's body is spooled while it downloads (#2029). Only
# ``fetch.get_config`` writes it and only its parse reads it; nothing treats it
# as ``current`` or ``previous``.
FETCH_SPOOL = "config/fetch.json.part"

# The cached bundle a startup hold (#2019) sets aside, kept on disk rather than
# in memory (#2223). Only meaningful to the process that wrote it.
HELD_BUNDLE = "config/held.json"


def ensure_layout(state_dir: Path) -> None:
    for sub in ("config", "rendered", "tsig", "ops/inflight", "ops/failed"):
        (state_dir / sub).mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, 0o700)
    # A spool left by a process killed mid-download or mid-parse (an OOM kill
    # is the case #2029 is about) is up to a whole bundle of dead disk. The
    # next fetch would truncate it anyway; dropping it at start means a
    # crash-looping agent does not sit on it in the meantime.
    (state_dir / FETCH_SPOOL).unlink(missing_ok=True)
    # A hold is decided afresh by every start, from ``current.json``.
    (state_dir / HELD_BUNDLE).unlink(missing_ok=True)


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


# Value strings at most this long are shared while a bundle is parsed (#2029).
# A blocklist entry carries ``"action": "block"`` and ``"block_mode":
# "nxdomain"`` and ``json`` builds a fresh str for every occurrence — 1.4M
# entries spend ~135 MB of a ~520 MB parse on copies of a handful of words.
# Domain names are left alone: they are long, nearly all distinct, and
# sharing them would only grow the memo.
_INTERN_MAX_LEN = 16

# How much of the file the streaming parse reads at a time (#2223).
_PARSE_CHUNK = 1 << 18

_JSON_WS = " \t\n\r"

# What a number cut off inside its fraction or exponent leaves undecoded.
_NUMBER_TAIL = ".eE+-"

# How many levels below a top-level member a value too large for the buffer is
# decoded a member at a time: a blocklist, its ``entries``, one entry (a zone,
# its ``records``, one record), and one level to spare.
_DESCEND_DEPTH = 3

# Per top-level array, the member of each element ``records=False`` drops.
_RECORD_LEVEL = {"zones": "records", "blocklists": "entries"}


def _sharing_decoder(values: bool = True) -> tuple[json.JSONDecoder, dict[str, str]]:
    """A decoder sharing keys and short values across one whole parse.

    ``json`` shares the keys of one document through a memo it clears after
    every ``raw_decode``; the streaming parse decodes a bundle a zone at a
    time, so it keeps its own, for keys and for the short values #2029
    shares. Without it every zone would carry its own copies of ~37 key
    strings, ~40 MB at 20,000 zones. A memo rather than ``sys.intern``: a
    million records carry a million distinct short names and addresses, and
    the interpreter's intern table keeps its size after they are freed (~14
    MB at that scale); the memo goes with the parse.

    ``values=False`` shares keys only: a parse that drops the records must
    not keep every short value they carried alive in the memo meanwhile.
    """
    memo: dict[str, str] = {}
    share = memo.setdefault

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, value in items:
            if values and value.__class__ is str and len(value) <= _INTERN_MAX_LEN:
                value = share(value, value)
            obj[share(key, key)] = value
        return obj

    return json.JSONDecoder(object_pairs_hook=pairs), memo


class _TextStream:
    """A text file read a chunk at a time and decoded one JSON value at a time.

    Only what has not been consumed yet stays buffered, so the bundle's text
    is never in memory whole: about a chunk, more only for a single string or
    number longer than one.
    """

    def __init__(self, fh: Any, decoder: json.JSONDecoder) -> None:
        self._fh = fh
        self._decoder = decoder
        self.buf = ""
        self.pos = 0
        self._want = _PARSE_CHUNK
        self._eof = False

    def _read(self) -> bool:
        if self._eof:
            return False
        if self.pos > len(self.buf) // 2:
            self.buf = self.buf[self.pos :]
            self.pos = 0
        got = self._fh.read(self._want)
        if not got:
            self._eof = True
            return False
        self.buf += got
        return True

    def _grow(self) -> bool:
        # At least as much again as is buffered: a value larger than the buffer
        # costs a doubling series of attempts, not one per chunk.
        self._want = max(_PARSE_CHUNK, len(self.buf) - self.pos)
        return self._read()

    def peek(self) -> str:
        """The next non-whitespace character, ``""`` at the end of the file."""
        while True:
            buf, pos, n = self.buf, self.pos, len(self.buf)
            while pos < n and buf[pos] in _JSON_WS:
                pos += 1
            self.pos = pos
            if pos < n or not self._read():
                return buf[pos] if pos < n else ""

    def take(self, expected: str) -> str:
        """Consume the next character, which must be one of ``expected``."""
        ch = self.peek()
        if not ch or ch not in expected:
            raise json.JSONDecodeError(f"Expecting one of {expected!r}", self.buf, self.pos)
        self.pos += 1
        return ch

    def value(self, depth: int = 0) -> Any:
        """The next value.

        One that does not fit in what is buffered and is an array or object
        is decoded a member at a time, ``depth`` levels down, so its text is
        never held whole either: a single blocklist of 1.4M entries is one
        element of ``blocklists``, ~130 MB of text, and growing the buffer to
        hold it cost more than reading the file whole. Anything else is read
        further and decoded again.
        """
        ch = self.peek()
        while True:
            try:
                value, end = self._decoder.raw_decode(self.buf, self.pos)
            except json.JSONDecodeError:
                if depth > 0 and ch in "{[" and not self._eof:
                    return self._container(ch, depth - 1)
                if self._grow():
                    continue
                raise
            # A number cut off by the end of the buffer decodes as a shorter
            # one, so a number that may go on past the buffer is decoded again
            # with more. That includes one cut inside its fraction or
            # exponent: ``1.`` or ``1e+`` decodes as ``1`` and leaves ``.`` /
            # ``e+`` behind, which would then fail the parse of a valid bundle.
            if not self._cut_off(value, end) or not self._grow():
                self.pos = end
                return value

    def _cut_off(self, value: Any, end: int) -> bool:
        """Whether the number decoded up to ``end`` may continue past the buffer.

        Only a number can: a string, an array and an object end with their own
        delimiter, and ``true`` / ``false`` / ``null`` with their last letter.
        """
        if value.__class__ not in (int, float):
            return False
        tail = self.buf[end:]
        return len(tail) <= 2 and not tail.strip(_NUMBER_TAIL)

    def _container(self, ch: str, depth: int) -> Any:
        """An array or object decoded a member at a time; what ``raw_decode``
        would give, the object through the same pairs hook."""
        self.pos += 1
        if ch == "[":
            items: list[Any] = []
            if self.peek() == "]":
                self.pos += 1
                return items
            while True:
                items.append(self.value(depth))
                if self.take(",]") == "]":
                    return items
        pairs: list[tuple[str, Any]] = []
        if self.peek() != "}":
            while True:
                if self.peek() != '"':
                    raise json.JSONDecodeError(
                        "Expecting property name enclosed in double quotes", self.buf, self.pos
                    )
                key = self.value()
                self.take(":")
                pairs.append((key, self.value(depth)))
                if self.take(",}") == "}":
                    break
        else:
            self.pos += 1
        return self._decoder.object_pairs_hook(pairs)  # type: ignore[misc]

    def rest(self) -> str:
        while self._read():
            pass
        return self.buf[self.pos :]


def parse_bundle_file(path: Path, *, records: bool = True) -> Any:
    """Parse a bundle from disk without holding its text whole (#2029, #2223).

    The result is ``==`` to ``json.loads`` of the file. A bundle is an object
    whose large members are arrays (``zones``, ``blocklists``); each top-level
    array is decoded an element at a time, and an element too large for the
    buffer (a catalogue blocklist) a member at a time, so the text in memory
    is about one chunk rather than the whole document. Measured at 20,000 zones
    and a million records (a 126 MB file), peak RSS went from ~525 MB reading
    it whole to ~410 MB streamed. Shared keys and short values
    (``_sharing_decoder``) keep the parsed form as small as one ``json.loads``
    gives.

    ``records=False`` leaves out the record-level data — each zone's
    ``records``, each blocklist's ``entries`` — for a reader that needs only
    the zone list: each element's are freed as soon as it is read, so that
    reader holds one zone's or one blocklist's at a time, never the bundle's.
    """
    with path.open("rb") as raw:
        encoding = json.detect_encoding(raw.read(4))
    with path.open("r", encoding=encoding, errors="surrogatepass", newline="") as fh:
        decoder, memo = _sharing_decoder(values=records)
        stream = _TextStream(fh, decoder)
        if stream.peek() != "{":
            # Not an object (never a bundle): ``json`` decides, as before.
            return json.loads(stream.rest())
        stream.pos += 1
        bundle: dict[str, Any] = {}
        if stream.peek() == "}":
            stream.pos += 1
        else:
            while True:
                key = stream.value()
                if not isinstance(key, str):
                    raise json.JSONDecodeError(
                        "Expecting property name enclosed in double quotes",
                        stream.buf,
                        stream.pos,
                    )
                stream.take(":")
                if stream.peek() == "[":
                    stream.pos += 1
                    items: list[Any] = []
                    if stream.peek() == "]":
                        stream.pos += 1
                    else:
                        while True:
                            item = stream.value(_DESCEND_DEPTH)
                            if not records and key in _RECORD_LEVEL and isinstance(item, dict):
                                item.pop(_RECORD_LEVEL[key], None)
                            items.append(item)
                            if stream.take(",]") == "]":
                                break
                    value: Any = items
                else:
                    value = stream.value(_DESCEND_DEPTH)
                if value.__class__ is str and len(value) <= _INTERN_MAX_LEN:
                    value = memo.setdefault(value, value)
                bundle[memo.setdefault(key, key)] = value
                if stream.take(",}") == "}":
                    break
        if stream.peek():
            raise json.JSONDecodeError("Extra data", stream.buf, stream.pos)
        return bundle


def load_config(
    state_dir: Path, *, records: bool = True
) -> tuple[dict[str, Any] | None, str | None]:
    """The cached bundle. ``records=False``: without its record-level data
    (see ``parse_bundle_file``), for a reader that needs only the zone list."""
    cfg_path = state_dir / "config" / "current.json"
    etag_path = state_dir / "config" / "current.etag"
    if not cfg_path.exists():
        return None, None
    try:
        cfg = parse_bundle_file(cfg_path, records=records)
    except ValueError:
        # JSONDecodeError, and UnicodeDecodeError: the encoding is sniffed
        # from the first bytes (#2029), so a torn, NUL-filled file reads as
        # UTF-32 and fails to DECODE rather than to parse. Either way it is
        # no cache, never a crash at boot (non-negotiable #5).
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
        cfg = parse_bundle_file(cfg_path)
    except ValueError:
        # JSONDecodeError, and UnicodeDecodeError: the encoding is sniffed
        # from the first bytes (#2029), so a torn, NUL-filled file reads as
        # UTF-32 and fails to DECODE rather than to parse. Either way it is
        # no cache, never a crash at boot (non-negotiable #5).
        return None, None
    etag_path = cfg_dir / "previous.etag"
    etag = etag_path.read_text().strip() if etag_path.exists() else None
    return cfg, etag


def hold_bundle(state_dir: Path, etag: str) -> Path | None:
    """Keep the cached bundle on disk for a startup hold (#2019, #2223).

    The hold may have to serve this bundle later, after a fetch has replaced
    ``current.json``. Holding the parsed bundle for that meant the agent took
    its first bundle from the control plane with a second one already in
    memory: ~420 MB at 20,000 zones and a million records, on top of the
    ~500 MB the new one costs while it is parsed.

    A hard link, so it costs no disk: ``save_config`` replaces
    ``current.json`` by rename, which leaves this name on the old file. A
    copy where the filesystem refuses links. ``None`` — the caller keeps the
    parsed bundle instead — when ``current`` is not the bundle being held or
    neither could be written.
    """
    cfg_dir = state_dir / "config"
    current = cfg_dir / "current.json"
    held = state_dir / HELD_BUNDLE
    try:
        if (cfg_dir / "current.etag").read_text().strip() != etag:
            return None
        held.unlink(missing_ok=True)
        try:
            os.link(current, held)
        except OSError:
            shutil.copyfile(current, held)
    except OSError:
        log.warning("bootstrap_hold_copy_failed", path=str(held))
        held.unlink(missing_ok=True)
        return None
    return held


def load_held_bundle(path: Path) -> dict[str, Any] | None:
    try:
        return parse_bundle_file(path)  # type: ignore[no-any-return]
    except (OSError, ValueError):
        return None


def drop_held_bundle(state_dir: Path) -> None:
    (state_dir / HELD_BUNDLE).unlink(missing_ok=True)
