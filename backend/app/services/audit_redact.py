"""Read-side redaction of an audit row's ``old_value`` / ``new_value`` (#2009).

The audit writers are hundreds of hand-written call sites. They are
disciplined about it — a credential is recorded as ``<field>_set: true``,
never as its value — but nothing at the model level stops a writer putting
a credential-shaped value into the payload, and the payload is now returned
by the audit API and the ``get_audit_history`` MCP tool. So redaction runs
on READ, over whatever is stored, rather than trusting every writer:

* a dict key that looks like a credential (the support-bundle scrubber's
  ``SECRET_KEY_NAME_RE``: password / token / secret / ``*_key`` /
  ``*_encrypted`` / auth header / webhook URL ..., plus the few credential
  names in this codebase it does not match — the SNMP community and v3
  ``auth_pass`` / ``priv_pass``, ``*_key_pem``, ``headers``, ``creds``) has
  its value replaced;
* any string value is run through the same secret-VALUE patterns
  (JWTs, Fernet tokens, bearer strings, chat-webhook URLs, presigned-URL
  signatures ...), and a string
  carrying a PEM private key is replaced WHOLE — the shared pattern matches
  only the ``BEGIN`` line, which would leave the key body readable.

A boolean or integer under a credential-shaped key is kept: that is the
writers' ``smtp_password_set: true`` / ``token_count: 3`` convention, which
records whether a secret was set without recording it, and is exactly the
detail an operator opens the entry to see.

``changed_fields`` is a list of field NAMES, not values, and is returned
as stored.
"""

from __future__ import annotations

import re
from typing import Any

from app.services.support_bundle.scrub import looks_secret_key, redact_secrets

REDACTED = "[redacted]"
_MAX_DEPTH = 12

# Credential field names in this codebase that ``SECRET_KEY_NAME_RE`` does not
# match. Anchored so ``communities`` (BGP route attributes) and
# ``header_names`` stay readable. ``*_enc`` is the SNMP v3 user's
# ``auth_pass_enc`` / ``priv_pass_enc`` ciphertext, and
# ``service_account_json`` the Google Cloud DNS key file — both are also
# caught by value shape today (a Fernet token, a PEM private key), but the
# name is the defence that does not depend on the value's encoding (#2015).
_EXTRA_SECRET_KEY_RE = re.compile(
    r"((^|_)community$|(^|_)pass$|key_pem$|otpauth|(^|_)creds?$|(^|_)headers?$"
    r"|(^|_)enc$|service_account_json)",
    re.IGNORECASE,
)
_PEM_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")


def _secret_key(name: str) -> bool:
    return looks_secret_key(name) or bool(_EXTRA_SECRET_KEY_RE.search(name))


def _redact_string(value: str) -> str:
    if _PEM_PRIVATE_KEY_RE.search(value):
        return REDACTED
    return redact_secrets(value)[0]


def redact_audit_value(value: Any, _depth: int = 0) -> Any:
    """A copy of ``value`` with credential-shaped keys and strings redacted."""
    if _depth > _MAX_DEPTH:
        return REDACTED
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for k, v in value.items():
            if (
                _secret_key(str(k))
                and v not in (None, "", [], {})
                and not isinstance(v, bool | int)
            ):
                out[k] = REDACTED
            else:
                out[k] = redact_audit_value(v, _depth + 1)
        return out
    if isinstance(value, list):
        return [redact_audit_value(v, _depth + 1) for v in value]
    if isinstance(value, str):
        return _redact_string(value)
    return value


# The audit-row fields that carry writer-supplied content. Everything else on
# a serialized audit row (action, resource_type, user display name, ...) is a
# column the platform fills itself, and is shipped as is.
AUDIT_CONTENT_FIELDS = ("old_value", "new_value", "error_detail")


def redact_audit_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """A shallow copy of a serialized audit payload with its content redacted.

    For every surface that ships an audit row OUT of the box — the audit
    forwarders (syslog / webhook / SMTP), the typed-event outbox, and the
    copilot tools — so they show what the audit API shows (#2015). It returns
    a copy: the stored ``audit_log`` row is append-only and hash-chained, and
    is never touched. Idempotent, so a payload redacted upstream can pass
    through again unchanged.
    """
    out = dict(payload)
    for field in AUDIT_CONTENT_FIELDS:
        if field in out and out[field] is not None:
            out[field] = redact_audit_value(out[field])
    return out
