"""NFS backup destination (issue #971).

Nothing here reaches a real NFS server — CI has none. What it pins is
the part that fails *silently* if it drifts, plus the refusals.

**The struct constants are the point of this file.** The driver binds
``libnfs`` through :mod:`ctypes`, so ``struct nfs_stat_64`` and ``struct
nfsdirent`` are transcribed by hand from the C header. A wrong field
offset does not raise — it reads an adjacent field, so an archive
reports a plausible-but-wrong size, or a directory reads as a regular
file, or ``created_at`` comes back as a date that quietly reorders the
retention sweep. The expected values below were produced by compiling
``offsetof()`` against Debian trixie's ``libnfs-dev`` (libnfs 5.0.2) on
the same LP64 layout both shipped architectures use, so this asserts
against the compiler rather than against a re-derivation of the same
guess.

The live half — mount, read/write round-trip on both protocol versions,
atomic rename, squash and read-only error mapping — was validated
against an ``nfs-ganesha`` export during development and is not
reproducible in CI without a server.
"""

from __future__ import annotations

import ctypes
import errno
import os

import pytest

from app.services.backup.targets import DESTINATIONS, get_destination, libnfs_client
from app.services.backup.targets.base import DestinationConfigError, InvalidArchiveNameError
from app.services.backup.targets.libnfs_client import (
    NfsConnection,
    NfsError,
    _NfsDirent,
    _NfsStat64,
    _NfsUrl,
    build_url,
    connect,
)
from app.services.backup.targets.nfs import (
    _PART_SUFFIX,
    ARCHIVE_NAME_RE,
    NfsDestination,
    _remote_path,
    _squash_hint,
)

# ── struct layout, against the C compiler ─────────────────────────────


def test_nfs_stat64_layout_matches_the_c_header():
    assert ctypes.sizeof(_NfsStat64) == 136
    assert _NfsStat64.nfs_mode.offset == 16
    assert _NfsStat64.nfs_size.offset == 56
    assert _NfsStat64.nfs_mtime.offset == 88


def test_nfsdirent_layout_matches_the_c_header():
    assert ctypes.sizeof(_NfsDirent) == 160
    expected = {
        "next": 0,
        "name": 8,
        "inode": 16,
        "type": 24,
        "mode": 28,
        "size": 32,
        "atime": 40,
        "mtime": 56,
        "ctime": 72,
        "uid": 88,
        "gid": 92,
        "nlink": 96,
        "dev": 104,
        "rdev": 112,
        "blksize": 120,
        "blocks": 128,
        "used": 136,
        "atime_nsec": 144,
        "mtime_nsec": 148,
        "ctime_nsec": 152,
    }
    for field, offset in expected.items():
        assert getattr(_NfsDirent, field).offset == offset, field


def test_nfs_url_layout_matches_the_c_header():
    assert ctypes.sizeof(_NfsUrl) == 24


# ── URL composition ───────────────────────────────────────────────────


def test_build_url_defaults_to_v4_and_disables_autoreconnect():
    url = build_url(server="nas.example", export="/volume1/backups")
    assert url.startswith("nfs://nas.example/volume1/backups?")
    assert "version=4" in url
    # libnfs otherwise reconnects forever, like a kernel client. Right
    # for a filesystem, wrong for a scheduled job: a dead NAS would hold
    # the beat sweep's thread instead of failing the run.
    assert "autoreconnect=0" in url


def test_build_url_carries_port_uid_gid():
    url = build_url(
        server="10.0.0.5", export="/srv/backups", version=3, port=2050, uid=1000, gid=1000
    )
    assert "version=3" in url
    assert "nfsport=2050" in url
    # v3 additionally reaches mountd through the portmapper; an operator
    # who pinned one port has almost always pinned both.
    assert "mountport=2050" in url
    assert "uid=1000" in url and "gid=1000" in url


def test_build_url_normalises_a_missing_leading_slash():
    assert build_url(server="h", export="vol1").startswith("nfs://h/vol1?")


def test_build_url_omits_uid_when_unset():
    # Blank must mean "the identity the process runs as", not uid 0 —
    # presenting root to a root_squash export is the failure mode the
    # field exists to avoid.
    assert "uid=" not in build_url(server="h", export="/e")


# ── write sizing and teardown, against a stubbed libnfs ───────────────


class _FakeLib:
    """Stands in for the ``ctypes.CDLL``. Records the WRITE spans the
    client issues and whether the context was destroyed. Each test sets
    the server limit and the queue state.
    """

    def __init__(self, *, writemax: int = 0, queued: int = 0, fd: int = -1) -> None:
        self.writemax = writemax
        self.queued = queued
        self.fd = fd
        self.spans: list[tuple[int, int, bytes]] = []
        self.destroyed = False
        self._url = _NfsUrl(b"nas", b"/e", None)

    # NfsConnection.write
    def nfs_get_writemax(self, ctx):
        return self.writemax

    def nfs_open(self, ctx, path, flags, handle):
        return 0

    def nfs_pwrite(self, ctx, fh, offset, count, buf):
        self.spans.append((offset, count, ctypes.string_at(buf.value, count)))
        return count

    def nfs_close(self, ctx, fh):
        return 0

    def nfs_get_error(self, ctx):
        return b""

    # connect
    def nfs_init_context(self):
        return 1

    def nfs_set_timeout(self, ctx, ms):
        pass

    def nfs_set_tcp_syncnt(self, ctx, n):
        pass

    def nfs_parse_url_dir(self, ctx, url):
        return ctypes.pointer(self._url)

    def nfs_mount(self, ctx, server, path):
        return 0

    def nfs_destroy_url(self, url):
        pass

    def nfs_queue_length(self, ctx):
        return self.queued

    def nfs_get_fd(self, ctx):
        return self.fd

    def nfs_destroy_context(self, ctx):
        self.destroyed = True


def _write_through(lib: _FakeLib, data: bytes) -> list[tuple[int, int, bytes]]:
    NfsConnection(lib, ctypes.c_void_p(1), describe="nas:/e").write("/a.zip.part", data)  # type: ignore[arg-type]
    return lib.spans


def _assert_reassembles(spans, data: bytes) -> None:
    offset = 0
    for at, count, payload in spans:
        assert at == offset
        assert payload == data[offset : offset + count]
        offset += count
    assert offset == len(data)


def test_v4_write_stays_under_the_server_limit_when_libnfs_does_not_know_it():
    """libnfs 5.0.2 leaves ``writemax`` at 0 on NFSv4 and sends each
    ``nfs_pwrite`` as one WRITE. A Synology DSM 7 export (limit 128 KiB)
    dropped the connection on every 1 MiB WRITE, so every v4 backup
    failed. With no negotiated limit, writes must go out in small pieces.
    """
    data = os.urandom(300 * 1024 + 7)
    spans = _write_through(_FakeLib(writemax=0), data)
    assert max(count for _, count, _ in spans) <= 64 * 1024
    _assert_reassembles(spans, data)


@pytest.mark.parametrize(
    "writemax, expected",
    [
        (32 * 1024, 32 * 1024),  # a server smaller than the v4 fallback
        (128 * 1024, 128 * 1024),  # the v3 FSINFO wtmax of the Synology above
        (4 * 1024 * 1024, 1024 * 1024),  # never above the per-call bound
    ],
)
def test_write_uses_the_limit_libnfs_negotiated(writemax, expected):
    data = os.urandom(3 * 1024 * 1024 + 11)
    spans = _write_through(_FakeLib(writemax=writemax), data)
    assert max(count for _, count, _ in spans) == expected
    _assert_reassembles(spans, data)


def test_a_dead_session_is_not_destroyed_but_its_socket_is_closed(monkeypatch):
    """libnfs 5.0.2 leaves a request queued when the connection dies
    under a sync call, with callback data on a stack frame that is gone.
    ``nfs_destroy_context`` runs that callback, and the api pod died with
    SIGSEGV right after a failed v4 write. A queued request at teardown
    means exactly that state, so the context must be left alone (leaked)
    and only its socket closed.
    """
    sock, other = os.pipe()
    os.close(other)
    lib = _FakeLib(queued=2, fd=sock)
    monkeypatch.setattr(libnfs_client, "_LIB", lib)
    try:
        with pytest.raises(NfsError):
            with connect(server="nas", export="/e"):
                raise NfsError("write failed: nfs_service failed", errno=errno.EIO)
        assert not lib.destroyed, "destroying a dead libnfs 5.0.2 session segfaults"
        with pytest.raises(OSError):
            os.fstat(sock)  # closed, so a failed run does not leak a socket
    finally:
        try:
            os.close(sock)
        except OSError:
            pass


def test_a_healthy_session_is_destroyed(monkeypatch):
    lib = _FakeLib(queued=0)
    monkeypatch.setattr(libnfs_client, "_LIB", lib)
    with connect(server="nas", export="/e"):
        pass
    assert lib.destroyed


def test_the_new_prototypes_are_declared(monkeypatch):
    """Same rule as every other binding in ``_load``: an undeclared
    restype is ``c_int``, which would truncate the uint64 ``writemax``.
    """

    class _Fn:
        pass

    class _Recorder:
        def __init__(self) -> None:
            self.fns: dict[str, _Fn] = {}

        def __getattr__(self, name: str) -> _Fn:
            return self.fns.setdefault(name, _Fn())

    rec = _Recorder()
    monkeypatch.setattr(libnfs_client.ctypes, "CDLL", lambda _name: rec)
    libnfs_client._load()
    assert rec.nfs_get_writemax.restype is ctypes.c_uint64
    assert rec.nfs_get_writemax.argtypes == [ctypes.c_void_p]
    for name in ("nfs_queue_length", "nfs_get_fd"):
        assert getattr(rec, name).restype is ctypes.c_int, name
        assert getattr(rec, name).argtypes == [ctypes.c_void_p], name


# ── path composition ──────────────────────────────────────────────────


def test_remote_path_composes_the_subdirectory():
    cfg = {"server": "h", "export": "/e", "path": "archives"}
    assert _remote_path(cfg, "a.zip") == "/archives/a.zip"
    assert _remote_path(cfg) == "/archives"


def test_remote_path_without_a_subdirectory():
    cfg = {"server": "h", "export": "/e"}
    assert _remote_path(cfg, "a.zip") == "/a.zip"
    assert _remote_path(cfg) == "/"


def test_remote_path_refuses_a_filename_that_is_not_one_component():
    # The same defence every other driver applies: an operator-supplied
    # filename must not escape the configured directory. Refused rather
    # than stripped since #1243 — stripping let ``..`` through unchanged.
    cfg = {"server": "h", "export": "/e", "path": "archives"}
    for bad in ("../../etc/passwd", "/abs/path/x.zip", ".."):
        with pytest.raises(InvalidArchiveNameError):
            _remote_path(cfg, bad)


def test_part_suffix_is_invisible_to_the_archive_regex():
    """The atomicity property, asserted directly.

    ``write`` stages to ``<name>.part`` and renames. That is only safe
    because the staged name cannot match the archive pattern — otherwise
    a killed write would leave a half-written file that ``list_archives``
    offers to the retention sweep and to ``latest/download``.
    """
    name = "spatiumddi-backup-20260907-120000.zip"
    assert ARCHIVE_NAME_RE.match(name)
    assert not ARCHIVE_NAME_RE.match(name + _PART_SUFFIX)


# ── config validation ─────────────────────────────────────────────────


@pytest.fixture
def driver() -> NfsDestination:
    return NfsDestination()


def test_minimal_config_is_accepted(driver):
    driver.validate_config({"server": "nas", "export": "/vol1/backups"})


@pytest.mark.parametrize(
    "config, because",
    [
        ({"export": "/e"}, "server missing"),
        ({"server": "h"}, "export missing"),
        ({"server": "", "export": "/e"}, "server empty"),
        ({"server": "h", "export": "/e", "version": "2"}, "version 2 is not a thing"),
        ({"server": "h", "export": "/e", "port": "0"}, "port below range"),
        ({"server": "h", "export": "/e", "port": "70000"}, "port above range"),
        ({"server": "h", "export": "/e", "uid": "root"}, "uid must be numeric"),
        ({"server": "h", "export": "/e", "timeout_s": "0"}, "timeout below range"),
        ({"server": "h", "export": "/e", "timeout_s": "99999"}, "timeout above range"),
    ],
)
def test_invalid_configs_are_refused(driver, config, because):
    with pytest.raises(DestinationConfigError):
        driver.validate_config(config)


@pytest.mark.parametrize("field", ["server", "export", "path"])
@pytest.mark.parametrize("bad", ["a?b", "a&b", "a#b", "a b", "a\tb"])
def test_url_hostile_characters_are_refused(driver, field, bad):
    """libnfs has no ``nfs_set_nfsport``, so the port and version travel
    as URL query arguments and the whole target is a URL. A ``?`` in an
    export path would silently truncate it into a query string, mounting
    something other than what the operator typed — so it is refused at
    validate time rather than mis-parsed at mount time.
    """
    config = {"server": "h", "export": "/e", field: bad}
    with pytest.raises(DestinationConfigError):
        driver.validate_config(config)


# ── errno → cause ─────────────────────────────────────────────────────


def test_permission_errors_name_both_likely_causes():
    """EACCES on NFS has two common causes needing opposite fixes, and the
    first cut named only one.

    The api runs unprivileged, so libnfs connects from an unprivileged
    source port — and Linux's ``secure`` export option (the default;
    Synology's equivalent is off by default) refuses exactly that. An
    operator told confidently that it "is almost always the squash
    setting" changes uid/gid and it never works.
    """
    hint = _squash_hint(NfsError("write failed", errno=errno.EACCES), action="write")
    assert "squash" in hint.lower()
    assert "uid" in hint.lower()
    assert "insecure" in hint.lower(), "the privileged-port cause must be named"
    assert "privileged" in hint.lower()


def test_eperm_is_treated_like_eacces():
    assert "squash" in _squash_hint(NfsError("x", errno=errno.EPERM), action="write").lower()


def test_read_only_export_says_so():
    hint = _squash_hint(NfsError("write failed", errno=errno.EROFS), action="write")
    assert "read-only" in hint.lower()
    assert "squash" not in hint.lower()


def test_out_of_space_and_quota_are_distinguished():
    assert "space" in _squash_hint(NfsError("x", errno=errno.ENOSPC), action="write").lower()
    assert "quota" in _squash_hint(NfsError("x", errno=errno.EDQUOT), action="write").lower()


def test_an_unmapped_errno_passes_through_unembellished():
    # Guessing at a cause we don't know would be worse than the raw
    # message — the operator can search the latter.
    exc = NfsError("mount failed: no route to host", errno=errno.EHOSTUNREACH)
    assert _squash_hint(exc, action="mount") == str(exc)


# ── registry ──────────────────────────────────────────────────────────


def test_nfs_is_registered_and_reflected():
    assert "nfs" in DESTINATIONS
    driver = get_destination("nfs")
    assert driver.kind == "nfs"
    names = {f.name for f in driver.config_fields}
    assert {"server", "export", "path", "version", "port", "uid", "gid"} <= names


def test_nfs_declares_no_secret_fields():
    """AUTH_SYS has no credential. A secret field here would imply the
    connection is authenticated, which is the single most important
    thing about this destination for an operator to understand.
    """
    assert not [f for f in get_destination("nfs").config_fields if f.secret]


def test_the_authentication_caveat_is_carried_as_a_notice_field():
    notices = [f for f in get_destination("nfs").config_fields if f.type == "notice"]
    assert len(notices) == 1
    body = (notices[0].description or "").lower()
    assert "auth_sys" in body or "no credential" in body
    # A notice is prose, never an input — the frontend renders it without
    # one, and it must not be required or the form could not be saved.
    assert notices[0].required is False


def test_notice_fields_are_not_part_of_the_validated_config():
    """The notice is decorative. If a client posts its name as a config
    key anyway, validation must not care — and it must never be
    *required*, which would make the kind unusable.
    """
    driver = get_destination("nfs")
    driver.validate_config({"server": "h", "export": "/e", "_auth_notice": "whatever"})


# ── copilot surface ───────────────────────────────────────────────────


def test_the_copilot_kind_filter_enumerates_every_registered_kind():
    """The ``kind`` filter's description is what the model reads to
    decide which values are legal, so a hand-written list there does not
    just go stale — it makes a registered destination unaskable-about.
    It is now derived from the registry; this pins that it resolves to a
    non-empty list containing the newest kind.

    The empty case is the one worth guarding: the registry lives in
    ``targets.base`` but is filled by ``targets.__init__``, so reading
    the wrong module yields ``""`` silently.
    """
    from app.services.ai.tools.backup import ListBackupTargetsArgs, _known_kinds

    kinds = _known_kinds()
    assert "nfs" in kinds
    assert len(kinds) >= 9
    described = ListBackupTargetsArgs.model_fields["kind"].description or ""
    assert "nfs" in described
    for kind in kinds:
        assert kind in described, f"{kind} missing from the tool description"
