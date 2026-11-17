"""Guard for #3644: a handler-level 403 must leave exactly one ``denied`` row.

The central 403 handler in ``app.main`` writes the row unless the code already
did (``note_denial_audited()``). Two ways to break that, both pinned here:

* the handler is unregistered -> handler-level refusals go unaudited;
* new code writes its own ``denied`` AuditLog without ``note_denial_audited()``
  -> the handler writes a second row for the same refusal.
"""

from __future__ import annotations

import ast
from pathlib import Path

from starlette.exceptions import HTTPException as StarletteHTTPException

from app.main import app

APP_DIR = Path(__file__).resolve().parents[1] / "app"

# Functions that write a ``denied`` row for something that is not an HTTP 403
# (so the central handler never fires for it). relative file paths under app/.
_NOT_A_403 = {
    "services/dns/ddns.py",  # DDNS name conflict: no HTTP request involved
    "api/v1/auth/router.py",  # MFA enrol re-auth outcome row, not a 403 refusal
}


def _is_denied_audit_call(node: ast.AST) -> bool:
    if not (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "AuditLog"):
        return False
    for kw in node.keywords:
        if kw.arg == "result":
            return any(
                isinstance(n, ast.Constant) and n.value == "denied" for n in ast.walk(kw.value)
            )
    return False


def _calls_note(fn: ast.AST) -> bool:
    return any(
        isinstance(n, ast.Call)
        and (
            getattr(n.func, "id", None) == "note_denial_audited"
            or getattr(n.func, "attr", None) == "note_denial_audited"
        )
        for n in ast.walk(fn)
    )


def test_http_exception_handler_is_registered() -> None:
    handler = app.exception_handlers.get(StarletteHTTPException)
    assert handler is not None, "no StarletteHTTPException handler: handler-level 403s unaudited"
    assert handler.__name__ == "_http_exception_audited", handler


def test_every_denied_audit_writer_marks_the_request_audited() -> None:
    offenders: list[str] = []
    for path in sorted(APP_DIR.rglob("*.py")):
        rel = path.relative_to(APP_DIR).as_posix()
        if rel == "core/denial_audit.py" or rel in _NOT_A_403:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if _calls_note(fn):
                continue
            for node in ast.walk(fn):
                if _is_denied_audit_call(node):
                    offenders.append(f"app/{rel}:{node.lineno} in {fn.name}()")
    assert not offenders, (
        "These write a result='denied' AuditLog without note_denial_audited(); a 403 "
        "raised after them gets a second row from the central handler "
        "(app.core.denial_audit):\n  " + "\n  ".join(offenders)
    )
