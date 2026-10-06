"""Minimal userspace NFS client over ``libnfs`` (issue #971).

The ``nfs`` backup destination speaks NFSv3 / NFSv4 from inside the
unprivileged api / worker container. A kernel ``mount -t nfs`` needs
``CAP_SYS_ADMIN``, which is not something to hand the process that also
holds the Fernet master key — so, exactly as ``smb`` speaks SMB in
userspace via ``smbprotocol``, this speaks NFS in userspace via
`libnfs <https://github.com/sahlberg/libnfs>`_ (LGPL-2.1), **dynamically
linked** through :mod:`ctypes` against the distro's ``libnfs.so.14``.

Why ctypes rather than the obvious alternatives
-----------------------------------------------

The issue proposed libnfs's own Python binding (``libnfs`` on PyPI) with
a shell-out to ``libnfs-utils`` as the fallback. Both were tried first
and both are dead ends:

* **The PyPI binding cannot be imported on our Python.** ``libnfs
  1.0.post4`` is a 2016 sdist — the only release ever published — whose
  SWIG shim calls ``import imp`` at module scope. ``imp`` was removed in
  Python 3.12, which is the interpreter this image ships. It still
  *compiles* against libnfs 5.0.2, which makes the failure look like a
  packaging problem right up until the first import.
* **The CLI fallback cannot satisfy the ABC.** Debian's
  ``libnfs-utils`` ships exactly four binaries — ``nfs-cat``,
  ``nfs-cp``, ``nfs-ls``, ``nfs-stat``. There is no ``nfs-rm``, so
  :meth:`~app.services.backup.targets.base.BackupDestination.delete`
  could not be implemented, and a destination that cannot delete cannot
  do retention or clean up its own test probe. That is the same defect
  that rules TFTP out in #989, and it rules the shell-out out here.

ctypes against the shared library avoids both: no build toolchain in the
image (the runtime needs only the ``libnfs14`` package, not
``libnfs-dev``), no third-party Python package to age out from under us,
and dynamic linking keeps the LGPL obligation to the simple case.

Scope
-----

Deliberately small — the seven operations the destination driver needs,
synchronous, one connection per operation. There is no connection
pooling and no attempt to wrap the async half of libnfs: an
``nfs_context`` is not thread-safe, and the driver already runs every
call inside :func:`asyncio.to_thread`, so a per-call context is both the
simplest and the correct lifetime.

Portability note: the struct layouts below assume LP64 with natural
alignment, which covers both architectures we ship (non-negotiable #11).
``tests/test_backup_target_nfs.py`` pins the sizes and offsets so a
layout that drifts fails loudly rather than reading a garbage field.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime

__all__ = [
    "NfsError",
    "NfsUnavailableError",
    "NfsDirent",
    "NfsStat",
    "NfsConnection",
    "connect",
]


class NfsError(Exception):
    """An NFS operation failed. ``errno`` carries libnfs's negative
    return code as a positive errno where one was supplied (0 when the
    failure had no errno, e.g. a mount refusal), so callers can map
    ``EACCES`` / ``EPERM`` / ``EROFS`` onto operator-readable causes
    instead of surfacing a bare number.
    """

    def __init__(self, message: str, *, errno: int = 0) -> None:
        super().__init__(message)
        self.errno = errno


class NfsUnavailableError(NfsError):
    """``libnfs.so`` is not present in this image. Raised on first use
    rather than at import so that an install which never configures an
    NFS destination is unaffected by the library being absent — and so
    the operator gets a sentence naming the package instead of an
    ``OSError`` from the loader.
    """


# ── C types ───────────────────────────────────────────────────────────

_u64 = ctypes.c_uint64
_u32 = ctypes.c_uint32


class _Timeval(ctypes.Structure):
    """``struct timeval`` — LP64: two 64-bit longs."""

    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class _NfsStat64(ctypes.Structure):
    """``struct nfs_stat_64`` — 17 consecutive ``uint64_t``."""

    _fields_ = [
        ("nfs_dev", _u64),
        ("nfs_ino", _u64),
        ("nfs_mode", _u64),
        ("nfs_nlink", _u64),
        ("nfs_uid", _u64),
        ("nfs_gid", _u64),
        ("nfs_rdev", _u64),
        ("nfs_size", _u64),
        ("nfs_blksize", _u64),
        ("nfs_blocks", _u64),
        ("nfs_atime", _u64),
        ("nfs_mtime", _u64),
        ("nfs_ctime", _u64),
        ("nfs_atime_nsec", _u64),
        ("nfs_mtime_nsec", _u64),
        ("nfs_ctime_nsec", _u64),
        ("nfs_used", _u64),
    ]


class _NfsDirent(ctypes.Structure):
    """``struct nfsdirent``. The fields past ``inode`` are populated
    from READDIRPLUS (v3) / READDIR-with-attributes (v4) — a server that
    declines to return them leaves zeroes, which
    :meth:`NfsConnection.listdir` detects and back-fills with an
    explicit stat rather than reporting a 0-byte archive.
    """


_NfsDirent._fields_ = [
    ("next", ctypes.POINTER(_NfsDirent)),
    ("name", ctypes.c_char_p),
    ("inode", _u64),
    ("type", _u32),
    ("mode", _u32),
    ("size", _u64),
    ("atime", _Timeval),
    ("mtime", _Timeval),
    ("ctime", _Timeval),
    ("uid", _u32),
    ("gid", _u32),
    ("nlink", _u32),
    ("dev", _u64),
    ("rdev", _u64),
    ("blksize", _u64),
    ("blocks", _u64),
    ("used", _u64),
    ("atime_nsec", _u32),
    ("mtime_nsec", _u32),
    ("ctime_nsec", _u32),
]


class _NfsUrl(ctypes.Structure):
    _fields_ = [
        ("server", ctypes.c_char_p),
        ("path", ctypes.c_char_p),
        ("file", ctypes.c_char_p),
    ]


#: ``NF3REG`` from ``libnfs-raw-nfs.h`` — a regular file. Used to skip
#: directories in a listing without a stat per entry.
_NF3REG = 1

#: ``S_IFREG``/``S_IFMT`` for the same test off ``mode`` when a server
#: fills ``mode`` but leaves ``type`` at zero.
_S_IFMT = 0o170000
_S_IFREG = 0o100000

#: The ONE soname whose ABI this module was written against — Debian's
#: ``libnfs14`` (libnfs 5.0.2), which the backend image installs.
#:
#: Deliberately not a fallback list, and deliberately not
#: ``ctypes.util.find_library("nfs")``. A soname bump exists *because*
#: the ABI changed: libnfs 6.0 swapped ``nfs_pread`` / ``nfs_pwrite`` to
#: POSIX ``(buf, count, offset)`` order, so binding a future
#: ``libnfs.so.15`` with these prototypes would pass the buffer pointer
#: as an offset and a NULL as the buffer — a segfault on write, and a
#: silently empty read. The struct layouts have the same exposure: a
#: wrong ``nfsdirent`` offset does not raise, it returns an adjacent
#: field, and a garbage ``mtime`` flows into ``created_at``, which the
#: ``retention_keep_days`` sweep compares against a cutoff and then
#: DELETES on.
#:
#: A refusal to load is recoverable and names the package. A wrong-ABI
#: bind destroys backups while reporting success, so this fails closed.
_SONAME = "libnfs.so.14"


# ── library loading ───────────────────────────────────────────────────


def _load() -> ctypes.CDLL:
    """Load ``libnfs`` and declare every prototype we call.

    Declaring ``argtypes`` / ``restype`` is not optional hygiene here:
    ctypes defaults an undeclared return to ``c_int``, which truncates
    every pointer this API hands back to 32 bits. That corrupts silently
    on the first allocation above 4 GiB rather than failing at the call.
    """
    try:
        lib = ctypes.CDLL(_SONAME)
    except OSError as exc:
        raise NfsUnavailableError(
            "the NFS backup destination needs the libnfs shared library, "
            f"which is not present in this image: could not load {_SONAME} "
            f"({exc}). Install the Debian package 'libnfs14'. Note that only "
            "this soname is accepted — see the comment on _SONAME for why a "
            "different ABI is refused rather than used."
        ) from exc

    ctx = ctypes.c_void_p
    fh = ctypes.c_void_p
    d = ctypes.c_void_p

    lib.nfs_init_context.restype = ctx
    lib.nfs_init_context.argtypes = []
    lib.nfs_destroy_context.restype = None
    lib.nfs_destroy_context.argtypes = [ctx]
    # ``nfs_get_error`` returns a pointer into the context; c_char_p
    # copies it out as bytes, which is what we want — the context is
    # destroyed before the message is used.
    lib.nfs_get_error.restype = ctypes.c_char_p
    lib.nfs_get_error.argtypes = [ctx]

    lib.nfs_parse_url_dir.restype = ctypes.POINTER(_NfsUrl)
    lib.nfs_parse_url_dir.argtypes = [ctx, ctypes.c_char_p]
    lib.nfs_destroy_url.restype = None
    lib.nfs_destroy_url.argtypes = [ctypes.POINTER(_NfsUrl)]

    lib.nfs_mount.restype = ctypes.c_int
    lib.nfs_mount.argtypes = [ctx, ctypes.c_char_p, ctypes.c_char_p]
    lib.nfs_set_timeout.restype = None
    lib.nfs_set_timeout.argtypes = [ctx, ctypes.c_int]
    lib.nfs_set_autoreconnect.restype = None
    lib.nfs_set_autoreconnect.argtypes = [ctx, ctypes.c_int]
    lib.nfs_set_tcp_syncnt.restype = None
    lib.nfs_set_tcp_syncnt.argtypes = [ctx, ctypes.c_int]
    # The server's WRITE limit as libnfs learned it at mount. uint64_t,
    # and 0 on NFSv4 in 5.0.2 — see ``NfsConnection._write_chunk``.
    lib.nfs_get_writemax.restype = _u64
    lib.nfs_get_writemax.argtypes = [ctx]
    # Teardown introspection for ``connect``'s dead-session guard.
    lib.nfs_queue_length.restype = ctypes.c_int
    lib.nfs_queue_length.argtypes = [ctx]
    lib.nfs_get_fd.restype = ctypes.c_int
    lib.nfs_get_fd.argtypes = [ctx]

    lib.nfs_open.restype = ctypes.c_int
    lib.nfs_open.argtypes = [ctx, ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(fh)]
    lib.nfs_creat.restype = ctypes.c_int
    lib.nfs_creat.argtypes = [ctx, ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(fh)]
    lib.nfs_close.restype = ctypes.c_int
    lib.nfs_close.argtypes = [ctx, fh]
    # NOTE the argument order: libnfs takes (offset, count, buf), not
    # POSIX's (buf, count, offset).
    lib.nfs_pread.restype = ctypes.c_int
    lib.nfs_pread.argtypes = [ctx, fh, _u64, _u64, ctypes.c_void_p]
    lib.nfs_pwrite.restype = ctypes.c_int
    lib.nfs_pwrite.argtypes = [ctx, fh, _u64, _u64, ctypes.c_void_p]

    lib.nfs_stat64.restype = ctypes.c_int
    lib.nfs_stat64.argtypes = [ctx, ctypes.c_char_p, ctypes.POINTER(_NfsStat64)]
    lib.nfs_unlink.restype = ctypes.c_int
    lib.nfs_unlink.argtypes = [ctx, ctypes.c_char_p]
    lib.nfs_rename.restype = ctypes.c_int
    lib.nfs_rename.argtypes = [ctx, ctypes.c_char_p, ctypes.c_char_p]
    lib.nfs_mkdir.restype = ctypes.c_int
    lib.nfs_mkdir.argtypes = [ctx, ctypes.c_char_p]

    lib.nfs_opendir.restype = ctypes.c_int
    lib.nfs_opendir.argtypes = [ctx, ctypes.c_char_p, ctypes.POINTER(d)]
    lib.nfs_readdir.restype = ctypes.POINTER(_NfsDirent)
    lib.nfs_readdir.argtypes = [ctx, d]
    lib.nfs_closedir.restype = None
    lib.nfs_closedir.argtypes = [ctx, d]
    return lib


_LIB: ctypes.CDLL | None = None


def _lib() -> ctypes.CDLL:
    global _LIB
    if _LIB is None:
        _LIB = _load()
    return _LIB


# ── public value types ────────────────────────────────────────────────


@dataclass(frozen=True)
class NfsStat:
    size: int
    mtime: datetime
    mode: int

    @property
    def is_regular_file(self) -> bool:
        return (self.mode & _S_IFMT) == _S_IFREG


@dataclass(frozen=True)
class NfsDirent:
    name: str
    size: int
    mtime: datetime
    is_regular_file: bool
    #: True when the server returned no attributes with the entry, so
    #: ``size`` / ``mtime`` are placeholders the caller must stat for.
    attrs_missing: bool = False


# ``O_*`` are the kernel's, and libnfs passes them straight through to
# its own translation. Naming them locally keeps the module readable
# and avoids depending on ``os.O_*`` having the same value on a
# platform we might later cross-compile for.
_O_RDONLY = 0
_O_WRONLY = 1
_O_CREAT = 0o100
_O_TRUNC = 0o1000

#: Upper bound for one ctypes read / write call. On NFSv3 libnfs splits
#: a larger call itself, by the rtmax / wtmax the server reported in
#: FSINFO. On NFSv4 it does NOT for writes — see ``_V4_WRITE_CHUNK``.
_CHUNK = 1024 * 1024

#: Per-call WRITE size when libnfs does not know the server's limit,
#: which on libnfs 5.0.2 is every NFSv4 mount (#1500).
#:
#: 5.0.2 only fills ``writemax`` from the v3 FSINFO reply. On v4 it stays
#: 0, and ``nfs_pwrite`` goes out as ONE WRITE of whatever size it was
#: handed. A server whose limit is below that drops the connection rather
#: than returning an error: libnfs reports EIO "nfs_service failed", the
#: session is dead, and every call after it fails the same way. Against a
#: Synology DSM 7 export (FSINFO wtmax 128 KiB) every 1 MiB WRITE did
#: this, so every v4 backup failed while v3 worked. libnfs learned to
#: read FATTR4_MAXWRITE at mount only in 7.0.0, behind a soname we
#: refuse (see ``_SONAME``).
#:
#: 64 KiB is below any limit we know of in practice: Linux knfsd sizes
#: its limit from RAM and only goes under 64 KiB below 256 MiB, and
#: FreeBSD's default is 128 KiB. Measured over v4 against the Synology:
#: 32 / 64 / 128 KiB all fine, 160 KiB and up all failed. A 16 MiB
#: write + read-back took 0.57 s at 64 KiB against 0.42 s at 128 KiB.
#:
#: READ needs no counterpart. A server returns at most its own limit
#: and ``read`` already loops on short reads. 1 MiB READs over v4
#: worked against the same server that rejected 160 KiB WRITEs.
_V4_WRITE_CHUNK = 64 * 1024


class NfsConnection:
    """A mounted NFS export. Not thread-safe — one per operation."""

    def __init__(self, lib: ctypes.CDLL, ctx: ctypes.c_void_p, *, describe: str) -> None:
        self._lib = lib
        self._ctx = ctx
        self._describe = describe

    # -- error plumbing --------------------------------------------------

    def _err(self, rc: int, what: str) -> NfsError:
        raw = self._lib.nfs_get_error(self._ctx)
        detail = raw.decode("utf-8", "replace") if raw else ""
        errno = -rc if rc < 0 else 0
        name = ""
        if errno:
            try:
                name = f" [{os.strerror(errno)}]"
            except ValueError:  # pragma: no cover - out-of-range errno
                name = ""
        message = f"{what} failed on {self._describe}{name}"
        if detail:
            message = f"{message}: {detail}"
        return NfsError(message, errno=errno)

    def _write_chunk(self) -> int:
        """Bytes per ``nfs_pwrite`` call. The limit libnfs negotiated
        when it has one (v3). Otherwise ``_V4_WRITE_CHUNK``, because a
        WRITE over the server's limit kills the session (see there).
        """
        negotiated = int(self._lib.nfs_get_writemax(self._ctx))
        return min(_CHUNK, negotiated if negotiated > 0 else _V4_WRITE_CHUNK)

    # -- operations ------------------------------------------------------

    def stat(self, path: str) -> NfsStat:
        st = _NfsStat64()
        rc = self._lib.nfs_stat64(self._ctx, path.encode(), ctypes.byref(st))
        if rc < 0:
            raise self._err(rc, f"stat {path!r}")
        return NfsStat(
            size=int(st.nfs_size),
            mtime=datetime.fromtimestamp(int(st.nfs_mtime), UTC),
            mode=int(st.nfs_mode),
        )

    def listdir(self, path: str) -> list[NfsDirent]:
        handle = ctypes.c_void_p()
        rc = self._lib.nfs_opendir(self._ctx, path.encode(), ctypes.byref(handle))
        if rc < 0:
            raise self._err(rc, f"opendir {path!r}")
        out: list[NfsDirent] = []
        try:
            while True:
                entry = self._lib.nfs_readdir(self._ctx, handle)
                if not entry:
                    break
                e = entry.contents
                name = e.name.decode("utf-8", "replace") if e.name else ""
                if name in (".", ".."):
                    continue
                etype = int(e.type)
                emode = int(e.mode)
                # A server that returns no attributes leaves both at 0.
                # Reporting that entry as a 0-byte file would put a
                # bogus archive in front of the operator, so flag it and
                # let the caller stat.
                attrs_missing = etype == 0 and emode == 0
                if attrs_missing:
                    is_reg = True  # unknown; caller's stat decides
                elif etype:
                    is_reg = etype == _NF3REG
                else:
                    is_reg = (emode & _S_IFMT) == _S_IFREG
                out.append(
                    NfsDirent(
                        name=name,
                        size=int(e.size),
                        mtime=datetime.fromtimestamp(int(e.mtime.tv_sec), UTC),
                        is_regular_file=is_reg,
                        attrs_missing=attrs_missing,
                    )
                )
        finally:
            self._lib.nfs_closedir(self._ctx, handle)
        return out

    def read(self, path: str) -> bytes:
        handle = ctypes.c_void_p()
        rc = self._lib.nfs_open(self._ctx, path.encode(), _O_RDONLY, ctypes.byref(handle))
        if rc < 0:
            raise self._err(rc, f"open {path!r}")
        # A bytearray rather than a list + ``b"".join``: the join held a
        # second full copy at the moment it ran, so a 4 GB archive peaked
        # at ~8 GB RSS in a memory-limited api pod — an OOMKill during a
        # restore drill, which reads as "the drill failed".
        out = bytearray()
        buf = ctypes.create_string_buffer(_CHUNK)
        offset = 0
        try:
            while True:
                got = self._lib.nfs_pread(self._ctx, handle, offset, _CHUNK, buf)
                if got < 0:
                    raise self._err(got, f"read {path!r}")
                if got == 0:
                    break
                out += memoryview(buf)[:got]
                offset += got
        finally:
            self._lib.nfs_close(self._ctx, handle)
        return bytes(out)

    def write(self, path: str, data: bytes, *, mode: int = 0o640) -> None:
        handle = ctypes.c_void_p()
        rc = self._lib.nfs_open(
            self._ctx, path.encode(), _O_WRONLY | _O_CREAT | _O_TRUNC, ctypes.byref(handle)
        )
        if rc < 0:
            # ``nfs_open`` with O_CREAT is not universally honoured by
            # v3 servers; fall back to the explicit create, which also
            # lets us set the mode.
            rc2 = self._lib.nfs_creat(self._ctx, path.encode(), mode, ctypes.byref(handle))
            if rc2 < 0:
                # Report the CREAT's return code, not the OPEN's. The two
                # can differ (EINVAL from open on a v3 server, then EACCES
                # from creat under root_squash) and ``nfs_get_error`` now
                # holds the creat's message — pairing that text with the
                # open's errno makes ``_squash_hint`` give advice for a
                # failure that did not happen.
                raise self._err(rc2, f"create {path!r}")
        closed = False
        try:
            # Point straight into the caller's bytes rather than copying
            # each chunk into a ctypes buffer: ``from_buffer_copy`` per
            # iteration copied the whole archive an extra time (4 GB of
            # pure memcpy on a 4 GB archive) for nothing, since
            # ``nfs_pwrite`` takes a const pointer and never writes
            # through it.
            #
            # ``src`` is held in a local on purpose — it owns the
            # reference that keeps the bytes buffer alive for as long as
            # ``base`` is used as a raw address.
            src = ctypes.c_char_p(data)
            base = ctypes.cast(src, ctypes.c_void_p).value or 0
            offset = 0
            total = len(data)
            chunk = self._write_chunk()
            while offset < total:
                span = min(chunk, total - offset)
                put = self._lib.nfs_pwrite(
                    self._ctx, handle, offset, span, ctypes.c_void_p(base + offset)
                )
                if put < 0:
                    raise self._err(put, f"write {path!r}")
                if put == 0:
                    raise NfsError(f"write {path!r} made no progress on {self._describe}")
                offset += put
            # **The close is the durability barrier, not the last write.**
            # NFS writes go out UNSTABLE and libnfs issues the COMMIT at
            # close, so ENOSPC / EDQUOT / a server reboot between WRITE and
            # COMMIT are all reported HERE and nowhere earlier. Discarding
            # this return code (it used to live in a bare ``finally``) let
            # the driver rename a truncated archive into place and stamp
            # the run "success" — discovered only at restore.
            close_rc = self._lib.nfs_close(self._ctx, handle)
            closed = True
            if close_rc < 0:
                raise self._err(close_rc, f"commit of {path!r} on close")
        finally:
            if not closed:
                # An error above already has the operator's attention;
                # this close is only to release the server-side state.
                self._lib.nfs_close(self._ctx, handle)

    def unlink(self, path: str) -> None:
        rc = self._lib.nfs_unlink(self._ctx, path.encode())
        if rc < 0:
            raise self._err(rc, f"unlink {path!r}")

    def rename(self, old: str, new: str) -> None:
        rc = self._lib.nfs_rename(self._ctx, old.encode(), new.encode())
        if rc < 0:
            raise self._err(rc, f"rename {old!r} -> {new!r}")

    def mkdir(self, path: str) -> None:
        rc = self._lib.nfs_mkdir(self._ctx, path.encode())
        if rc < 0:
            raise self._err(rc, f"mkdir {path!r}")


def build_url(
    *,
    server: str,
    export: str,
    version: int = 4,
    port: int | None = None,
    uid: int | None = None,
    gid: int | None = None,
) -> str:
    """Compose the ``nfs://`` URL libnfs parses.

    The URL is the only way to reach several settings: libnfs exports no
    ``nfs_set_nfsport`` — the port is a URL argument or nothing — so the
    driver uses this form uniformly rather than keeping a second
    code path for the non-default-port case.

    ``autoreconnect=0`` is deliberate. libnfs defaults to reconnecting
    forever, like a kernel NFS client, which is right for a filesystem
    and wrong for a scheduled job: a dead NAS would hold the beat
    sweep's thread indefinitely instead of failing the run.
    """
    args = [f"version={int(version)}", "autoreconnect=0"]
    if port:
        args.append(f"nfsport={int(port)}")
        # v3 also reaches mountd through the portmapper; when the
        # operator has pinned a port they have almost always pinned
        # both, and libnfs otherwise still dials 111.
        if int(version) == 3:
            args.append(f"mountport={int(port)}")
    if uid is not None:
        args.append(f"uid={int(uid)}")
    if gid is not None:
        args.append(f"gid={int(gid)}")
    path = export if export.startswith("/") else "/" + export
    return f"nfs://{server}{path}?{'&'.join(args)}"


@contextmanager
def connect(
    *,
    server: str,
    export: str,
    version: int = 4,
    port: int | None = None,
    uid: int | None = None,
    gid: int | None = None,
    timeout_s: int = 30,
) -> Iterator[NfsConnection]:
    """Mount ``export`` on ``server`` and yield a connection.

    Every resource is released on the way out, including on the mount
    failure path — a leaked ``nfs_context`` holds a socket, and the beat
    sweep would accumulate one per failed run against a dead NAS.
    """
    lib = _lib()
    ctx = lib.nfs_init_context()
    if not ctx:
        raise NfsError("could not allocate an NFS context")
    describe = f"{server}:{export}"
    url_struct = None
    try:
        # Whole seconds only, per libnfs's own contract.
        lib.nfs_set_timeout(ctx, max(int(timeout_s), 1) * 1000)
        lib.nfs_set_tcp_syncnt(ctx, 2)
        url = build_url(server=server, export=export, version=version, port=port, uid=uid, gid=gid)
        url_struct = lib.nfs_parse_url_dir(ctx, url.encode())
        if not url_struct:
            raw = lib.nfs_get_error(ctx)
            detail = raw.decode("utf-8", "replace") if raw else "unparseable"
            raise NfsError(f"could not parse NFS URL for {describe}: {detail}")
        parsed = url_struct.contents
        # ``nfs_parse_url_dir`` applies the query arguments to the
        # context as a side effect; the struct only carries the split
        # server / path.
        rc = lib.nfs_mount(ctx, parsed.server, parsed.path)
        if rc < 0:
            raw = lib.nfs_get_error(ctx)
            detail = raw.decode("utf-8", "replace") if raw else ""
            # Unconditional: this is already inside ``if rc < 0``, so the
            # guard ``_err`` carries (where the helper cannot assume its
            # caller checked) would be dead here.
            errno = -rc
            raise NfsError(
                (
                    f"mount {describe} failed (NFSv{version}): {detail}"
                    if detail
                    else f"mount {describe} failed (NFSv{version})"
                ),
                errno=errno,
            )
        yield NfsConnection(lib, ctx, describe=describe)
    finally:
        if url_struct:
            lib.nfs_destroy_url(url_struct)
        _release_context(lib, ctx)


def _release_context(lib: ctypes.CDLL, ctx: ctypes.c_void_p) -> None:
    """Destroy ``ctx``, unless that would crash the process (#1500).

    In libnfs 5.0.2, when the connection dies under a synchronous call
    ("nfs_service failed"), the call returns but leaves its request
    queued. That request's callback data is a struct on the C stack of
    the call that already returned. ``nfs_destroy_context`` cancels
    every queued request and runs those callbacks, which then read and
    write a stack frame that no longer exists. Seen as SIGSEGV (exit
    139) of the api pod right after a failed v4 backup write: the run
    never got to record its failure, so the target stayed
    ``in_progress``. Upstream fixed it in 5.0.3 (libnfs commit db1cc8c)
    by failing the queued requests before the sync call returns.
    Debian's 5.0.2 package does not carry that fix.

    Every synchronous call waits until its own request is gone, so a
    request still queued here was left behind by a dead session. In
    that case close the socket ourselves (with autoreconnect off, libnfs
    does not close it on failure) and leak the context. That leaks the
    context and its queued requests (at most about one ``_CHUNK``) per
    dead session, which beats a segfault.
    """
    if lib.nfs_queue_length(ctx) > 0:
        fd = lib.nfs_get_fd(ctx)
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:  # pragma: no cover - already gone
                pass
        return
    lib.nfs_destroy_context(ctx)
