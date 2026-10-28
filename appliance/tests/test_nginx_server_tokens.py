"""Every nginx we ship hides its version (#2935).

nginx sends ``Server: nginx/<version>`` on every response, and prints the
version on its own error pages, unless ``server_tokens off`` is set. Version
and stack details are for signed-in users only, so every nginx config in
the tree carries it: the console image's template (Compose and plain k8s),
the chart's TLS template (the appliance and any ``frontend.tls`` install),
and the appliance's agent landing page, which runs the stock image with a
one-line ``conf.d`` drop-in rather than a config of its own.

Discovered, not listed: a new nginx server block, or a new chart workload
running the stock nginx image, fails here until it hides the version too.

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_nginx_server_tokens.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SEARCH_ROOTS = ("frontend", "charts", "k8s", "appliance/mkosi.extra", "agent")
SKIP_PARTS = {"node_modules", "dist", ".charts-render"}

_SERVER_BLOCK = re.compile(r"^[ \t]*server[ \t]*\{", re.MULTILINE)
_TOKENS_OFF = re.compile(r"^[ \t]*server_tokens[ \t]+off[ \t]*;", re.MULTILINE)
_NGINX_CONTAINER = re.compile(r"^[ \t]*-[ \t]*name:[ \t]*nginx[ \t]*$", re.MULTILINE)


def _candidates() -> list[Path]:
    out = []
    for root in SEARCH_ROOTS:
        for path in sorted((REPO / root).rglob("*")):
            if not path.is_file() or SKIP_PARTS & set(path.parts):
                continue
            if path.suffix not in {".conf", ".template", ".yaml", ".yml", ".tpl"}:
                continue
            out.append(path)
    return out


def _server_blocks(text: str) -> list[str]:
    """The body of every top-level-looking ``server {`` block, braces balanced."""
    bodies = []
    for match in _SERVER_BLOCK.finditer(text):
        depth, i = 1, match.end()
        while depth and i < len(text):
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        bodies.append(text[match.end() : i])
    return bodies


NGINX_CONFIGS = [
    p for p in _candidates() if _server_blocks(p.read_text(encoding="utf-8", errors="replace"))
]
STOCK_NGINX = [
    p
    for p in _candidates()
    if _NGINX_CONTAINER.search(p.read_text(encoding="utf-8", errors="replace"))
]


def test_the_known_configs_are_discovered() -> None:
    """Guards the discovery itself: a regex that finds nothing passes
    everything below."""
    rel = {str(p.relative_to(REPO)) for p in NGINX_CONFIGS}
    assert "frontend/default.conf.template" in rel
    assert "charts/spatiumddi/templates/frontend-tls-config.yaml" in rel
    assert "charts/spatiumddi-appliance/templates/agent-landing.yaml" in {
        str(p.relative_to(REPO)) for p in STOCK_NGINX
    }


@pytest.mark.parametrize("path", NGINX_CONFIGS, ids=lambda p: str(p.relative_to(REPO)))
def test_every_server_block_hides_the_version(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for body in _server_blocks(text):
        assert _TOKENS_OFF.search(body), f"{path}: a server block without server_tokens off"


@pytest.mark.parametrize("path", STOCK_NGINX, ids=lambda p: str(p.relative_to(REPO)))
def test_stock_nginx_workloads_get_the_drop_in(path: Path) -> None:
    """The stock nginx.conf includes ``conf.d/*.conf`` inside ``http {}``, so
    a drop-in there covers every server the image's default config defines."""
    text = path.read_text(encoding="utf-8")
    assert _TOKENS_OFF.search(text), f"{path}: no server_tokens off for the stock nginx"
    assert re.search(r"mountPath:[ \t]*/etc/nginx/conf\.d/[\w.-]+\.conf", text), (
        f"{path}: the server_tokens drop-in is not mounted into conf.d"
    )
