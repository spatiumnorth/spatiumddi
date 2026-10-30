"""uvicorn, bound to every address family the container has (#2308).

``--host 0.0.0.0`` is IPv4-only, so on an IPv6-only Kubernetes cluster (no IPv4
address on the pod) the probes and the Service cannot reach the api. ``--host
::`` is no better: uvicorn hands the host to ``loop.create_server``, and asyncio
sets ``IPV6_V6ONLY`` on every IPv6 socket it binds itself, so ``::`` serves IPv6
only whatever ``net.ipv6.bindv6only`` says (measured). That breaks Docker
Compose and IPv4 / dual-stack clusters the other way round.

A ``host`` of ``None`` is what asyncio documents for "all interfaces": it binds
one wildcard socket per family that exists, and skips a family the container
does not have, so this one entry point serves IPv4-only, dual-stack and
IPv6-only pods alike.

uvicorn's CLI has no way to say ``None``, so this runs its CLI unchanged and
only swaps the default host. An explicit ``--host``, ``UVICORN_HOST`` or
``API_BIND_HOST`` (the operator's own choice, e.g. ``127.0.0.1`` behind a
sidecar) is left exactly as given.

``--workers`` > 1 (or ``WEB_CONCURRENCY``) and ``--reload`` bind ONE socket in
the parent through ``Config.bind_socket``, which cannot take ``None`` (it raises
``TypeError``) and cannot bind two families. There the wrapper keeps the
pre-#2308 ``0.0.0.0`` and says so; an IPv6-only cluster running more than one
worker sets ``API_BIND_HOST=::`` (dual-stack under ``bind_socket``, which does
not set ``IPV6_V6ONLY``).
"""

from __future__ import annotations

import os
import sys

import uvicorn
from uvicorn.config import Config


def _host_pinned(argv: list[str]) -> bool:
    return (
        any(a == "--host" or a.startswith("--host=") for a in argv)
        or bool(os.environ.get("UVICORN_HOST"))
        or bool(os.environ.get("API_BIND_HOST"))
    )


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    bind_host = os.environ.get("API_BIND_HOST")
    if bind_host and not os.environ.get("UVICORN_HOST"):
        os.environ["UVICORN_HOST"] = bind_host
    if not _host_pinned(argv):
        original = Config.__init__

        def _init(self: Config, *args: object, **kwargs: object) -> None:
            original(self, *args, **kwargs)  # type: ignore[arg-type]
            if self.workers > 1 or self.reload:
                # One pre-bound socket (see the module docstring).
                self.host = "0.0.0.0"
                print(
                    "spatium_uvicorn: more than one worker (or --reload) binds a single "
                    "IPv4 socket; set API_BIND_HOST=:: on an IPv6-only cluster",
                    file=sys.stderr,
                )
            else:
                self.host = None  # type: ignore[assignment]  # all families, see above

        Config.__init__ = _init  # type: ignore[method-assign]
    uvicorn.main(args=argv, prog_name="uvicorn")


if __name__ == "__main__":
    main()
