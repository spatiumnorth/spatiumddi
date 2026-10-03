"""TACACS+ sign-in asks the server to authorize a login shell (#1336).

Once a password is accepted, the product asks the TACACS+ server for
authorization, to read the ``priv-lvl`` (or ``group``) it maps to internal
groups. It asked with no arguments at all. RFC 8907 section 8.2 says of the
``service`` argument "This argument MUST always be included", and of ``cmd``
that it "MUST be specified if service equals "shell"", with "an empty value"
for session-based shell authorization. Servers key their authorization
profiles on ``service``: tac_plus-ng's sample guards its profile with
``if (service == shell)``. Against such a profile the request was denied, the
reply carried no ``priv-lvl``, no group mapped, and every user was refused
"Invalid credentials" (``no_group_mapping_match``).

The server here speaks just enough RFC 8907 over a real socket for the
product's own client library: an ASCII login (START, GETPASS, CONTINUE) and
one authorization REQUEST, answered the way the strict profile above answers
it. It records every authorization request's arguments as they arrived on the
wire, so these tests see the bytes the product sends, not what it meant to.
"""

from __future__ import annotations

import socket
import socketserver
import struct
import threading
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.testing import capture_logs
from tacacs_plus.flags import (
    TAC_PLUS_AUTHEN,
    TAC_PLUS_AUTHEN_STATUS_FAIL,
    TAC_PLUS_AUTHEN_STATUS_GETPASS,
    TAC_PLUS_AUTHEN_STATUS_PASS,
    TAC_PLUS_AUTHOR,
    TAC_PLUS_AUTHOR_STATUS_FAIL,
    TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
)
from tacacs_plus.packet import TACACSHeader, TACACSPacket

from app.core.auth.tacacs import authenticate_tacacs
from app.core.crypto import encrypt_dict
from app.models.audit import AuditLog
from app.models.auth import Group, User
from app.models.auth_provider import AuthGroupMapping, AuthProvider

SECRET = "fx-tacacs-shared-secret"
USERS = {"tess": "tess-password", "dora": "dora-password"}
# A user the server knows but will not give a shell, however it is asked.
NO_SHELL = {"dora"}


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf


def _avpairs(args: list[bytes]) -> dict[str, tuple[str, bool]]:
    """``name=value`` (mandatory) or ``name*value`` (optional), RFC 8907 6.1."""
    out: dict[str, tuple[str, bool]] = {}
    for raw in args:
        arg = raw.decode()
        eq, star = arg.find("="), arg.find("*")
        cut = min(i for i in (eq, star) if i >= 0) if (eq >= 0 or star >= 0) else -1
        if cut < 0:
            continue
        out[arg[:cut]] = (arg[cut + 1 :], arg[cut] == "=")
    return out


class StrictTacacsServer:
    """A TACACS+ server on 127.0.0.1 holding the users in ``USERS``.

    Authorization is answered as tac_plus-ng's sample profile answers it::

        if (service == shell) { if (cmd == "") set priv-lvl = 15; permit }

    so a request without ``service=shell`` is refused (FAIL, no AV-pairs), and
    a user in ``NO_SHELL`` is refused whatever it asks for. ``author_requests``
    holds each authorization request's arguments, raw.
    """

    def __init__(self) -> None:
        self.author_requests: list[list[bytes]] = []
        self._lock = threading.Lock()
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                outer._serve(self.request)

        self._server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> StrictTacacsServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()

    def _serve(self, sock: socket.socket) -> None:
        sock.settimeout(5)
        user = ""
        while True:
            raw_header = _recv_exact(sock, 12)
            if not raw_header:
                return
            header = TACACSHeader.unpacked(raw_header)
            body = TACACSPacket(header, _recv_exact(sock, header.length), SECRET).body
            if header.type == TAC_PLUS_AUTHEN and header.seq_no == 1:
                # START: action, priv_lvl, authen_type, service, user/port/rem_addr/data lens.
                user_len = body[4]
                user = body[8 : 8 + user_len].decode()
                reply = self._authen_reply(TAC_PLUS_AUTHEN_STATUS_GETPASS, b"Password: ")
            elif header.type == TAC_PLUS_AUTHEN:
                # CONTINUE: user_msg len, data len, flags, then the password.
                (msg_len,) = struct.unpack("!H", body[:2])
                password = body[5 : 5 + msg_len].decode()
                ok = USERS.get(user) == password
                reply = self._authen_reply(
                    TAC_PLUS_AUTHEN_STATUS_PASS if ok else TAC_PLUS_AUTHEN_STATUS_FAIL, b""
                )
            elif header.type == TAC_PLUS_AUTHOR:
                reply = self._author_reply(body)
            else:
                return
            out = TACACSHeader(
                header.version, header.type, header.session_id, len(reply), seq_no=header.seq_no + 1
            )
            sock.sendall(bytes(TACACSPacket(out, reply, SECRET)))

    @staticmethod
    def _authen_reply(status: int, msg: bytes) -> bytes:
        return struct.pack("!BBHH", status, 0, len(msg), 0) + msg

    def _author_reply(self, body: bytes) -> bytes:
        # REQUEST: authen_method, priv_lvl, authen_type, authen_service,
        # user/port/rem_addr lens, arg_cnt, one length per argument, then the
        # user, port, rem_addr and the arguments.
        user_len, port_len, rem_len, arg_cnt = body[4], body[5], body[6], body[7]
        lens = list(body[8 : 8 + arg_cnt])
        off = 8 + arg_cnt + user_len + port_len + rem_len
        args = []
        for n in lens:
            args.append(body[off : off + n])
            off += n
        user = body[8 + arg_cnt : 8 + arg_cnt + user_len].decode()
        with self._lock:
            self.author_requests.append(args)
        pairs = _avpairs(args)
        if pairs.get("service", ("", True))[0] != "shell" or user in NO_SHELL:
            msg = b"not authorized"
            return struct.pack("!BBHH", TAC_PLUS_AUTHOR_STATUS_FAIL, 0, len(msg), 0) + msg
        grant = [b"priv-lvl=15"] if pairs.get("cmd", ("", True))[0] == "" else []
        head = struct.pack("!BBHH", TAC_PLUS_AUTHOR_STATUS_PASS_ADD, len(grant), 0, 0)
        return head + bytes(len(a) for a in grant) + b"".join(grant)


@pytest.fixture
def tacacs_server():
    with StrictTacacsServer() as server:
        yield server


def _provider(port: int, name: str = "tacacs-strict") -> AuthProvider:
    return AuthProvider(
        name=name,
        type="tacacs",
        is_enabled=True,
        priority=10,
        config={"server": "127.0.0.1", "port": port, "timeout": 5, "attr_groups": "priv-lvl"},
        secrets_encrypted=encrypt_dict({"secret": SECRET}),
        auto_create_users=True,
        auto_update_users=True,
    )


def test_a_strict_server_profile_authorizes_the_login(tacacs_server: StrictTacacsServer) -> None:
    result = authenticate_tacacs(_provider(tacacs_server.port), "tess", USERS["tess"])

    assert result is not None
    assert result.groups == ["priv-lvl:15"]


def test_the_request_asks_for_a_login_shell(tacacs_server: StrictTacacsServer) -> None:
    """RFC 8907 8.2: ``service`` always, and for a shell, ``cmd``, empty for a
    session (a sign-in), not a command."""
    authenticate_tacacs(_provider(tacacs_server.port), "tess", USERS["tess"])

    assert len(tacacs_server.author_requests) == 1
    pairs = _avpairs(tacacs_server.author_requests[0])
    assert pairs.get("service") == ("shell", True)  # mandatory
    assert pairs.get("cmd", ("<absent>", True))[0] == ""


def test_a_wrong_password_asks_for_no_authorization(tacacs_server: StrictTacacsServer) -> None:
    assert authenticate_tacacs(_provider(tacacs_server.port), "tess", "wrong") is None
    assert tacacs_server.author_requests == []


def test_a_refused_shell_still_maps_no_group_and_says_why(
    tacacs_server: StrictTacacsServer,
) -> None:
    """Fails closed, as before: a server that will not give this user a shell
    yields no group, so the sign-in is refused. Now it is also logged."""
    with capture_logs() as events:
        result = authenticate_tacacs(_provider(tacacs_server.port), "dora", USERS["dora"])

    assert result is not None and result.groups == []
    refused = [e for e in events if e.get("event") == "tacacs_authorization_refused"]
    assert len(refused) == 1
    assert refused[0]["username"] == "dora"
    assert refused[0]["server_msg"] == "not authorized"


@pytest.mark.asyncio
async def test_a_strict_server_profile_signs_the_user_in(
    client: AsyncClient, db_session: AsyncSession, tacacs_server: StrictTacacsServer
) -> None:
    """The issue's live case, end to end: the user signs in and lands in the
    group its ``priv-lvl`` maps to (it was 401 "Invalid credentials")."""
    group = Group(name=f"tacacs-ops-{uuid.uuid4().hex[:6]}", description="")
    provider = _provider(tacacs_server.port)
    db_session.add_all([group, provider])
    await db_session.flush()
    db_session.add(
        AuthGroupMapping(
            provider_id=provider.id, external_group="priv-lvl:15", internal_group_id=group.id
        )
    )
    await db_session.commit()

    r = await client.post(
        "/api/v1/auth/login", json={"username": "tess", "password": USERS["tess"]}
    )

    assert r.status_code == 200, r.text
    assert r.json()["access_token"]
    user = (await db_session.execute(select(User).where(User.username == "tess"))).scalar_one()
    assert user.auth_source == "tacacs"
    assert [g.name for g in await user.awaitable_attrs.groups] == [group.name]
    failures = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "login", AuditLog.result == "failure")
            )
        )
        .scalars()
        .all()
    )
    assert failures == []
