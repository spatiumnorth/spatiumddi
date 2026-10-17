"""Read-side redaction of an audit row's ``old_value`` / ``new_value`` (#2009).

The audit writers are ~120 hand-written call sites. Most store only plain
field values, but nothing at the model level stops a writer putting a
credential-shaped value into the payload, and the payload is now returned
by the audit API and the ``get_audit_history`` MCP tool. So redaction runs
on READ, over whatever is stored, rather than trusting every writer:

* a dict key that looks like a credential (the support-bundle scrubber's
  ``SECRET_KEY_NAME_RE``: password / token / secret / ``*_key`` /
  ``*_encrypted`` / auth header / webhook URL ...) has its value replaced;
* any string value is run through the same secret-VALUE patterns
  (JWTs, PEM blocks, bearer strings, chat-webhook URLs ...).

``changed_fields`` is a list of field NAMES, not values, and is returned
as stored.
"""

from __future__ import annotations

from typing import Any

from app.services.support_bundle.scrub import looks_secret_key, redact_secrets

REDACTED = "[redacted]"
_MAX_DEPTH = 12


def redact_audit_value(value: Any, _depth: int = 0) -> Any:
    """A copy of ``value`` with credential-shaped keys and strings redacted."""
    if _depth > _MAX_DEPTH:
        return REDACTED
    if isinstance(value, dict):
        return {
            k: (
                REDACTED
                if looks_secret_key(str(k)) and v not in (None, "", [], {})
                else redact_audit_value(v, _depth + 1)
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact_audit_value(v, _depth + 1) for v in value]
    if isinstance(value, str):
        return redact_secrets(value)[0]
    return value
