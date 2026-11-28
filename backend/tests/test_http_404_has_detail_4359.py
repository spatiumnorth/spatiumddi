"""Every ``HTTPException(404)`` under ``app/`` carries a ``detail`` (#4359).

A bare 404 is answered by FastAPI as ``{"detail": "Not Found"}``, so the
console's refused-delete line said only "Not Found" and the operator could not
tell which object was missing. Pure AST scan; no database, reads only
``backend/app``.
"""

from __future__ import annotations

import ast
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parent.parent / "app"


def _is_404(node: ast.expr) -> bool:
    s = ast.unparse(node)
    return s == "404" or s.endswith("HTTP_404_NOT_FOUND")


def _bare_404s() -> list[str]:
    offenders: list[str] = []
    for path in sorted(APP_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", None)
            if name != "HTTPException":
                continue
            kw = {k.arg: k.value for k in node.keywords}
            code = kw.get("status_code") or (node.args[0] if node.args else None)
            if code is None or not _is_404(code):
                continue
            if "detail" not in kw and len(node.args) < 2:
                offenders.append(f"{path.relative_to(APP_ROOT.parent)}:{node.lineno}")
    return offenders


def test_scanner_sees_a_bare_404() -> None:
    # Negative control: the scanner must flag the shape it exists to catch.
    tree = ast.parse("raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)")
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call))
    assert _is_404(call.keywords[0].value)


def test_no_404_without_detail() -> None:
    assert _bare_404s() == [], "HTTPException(404) without a detail names no object"
