"""Per-driver secret-field handling for backup-target ``config``
JSONB blobs (issue #117 Phase 1c).

Each :class:`BackupDestination` declares its config shape via a
tuple of :class:`ConfigFieldSpec`. Fields with ``secret=True`` —
S3's ``secret_access_key``, future SCP's ``ssh_private_key``,
Azure's ``account_key`` — must:

1. Never travel the wire in cleartext outside of POST / PATCH
   bodies (operators typing them in).
2. Be Fernet-encrypted at rest inside the ``config`` JSONB
   column.
3. Be redacted to a sentinel value (``"<set>"`` / ``""``) on
   every API read so even superadmins reviewing the row don't
   see the cleartext.

This module provides the four helpers the API layer + runner
call to enforce 1–3:

* :func:`encrypt_config_secrets` — runs after validate, before
  storage. Walks the driver's ``config_fields``; any ``secret``
  field with a non-empty plaintext value is encrypted via the
  shared :mod:`app.core.crypto` Fernet helper (same key path
  as auth provider creds + integration creds). The encrypted
  bytes are stored as ``"__enc__:<utf-8 of ciphertext>"`` so a
  later read can detect the wrapping by prefix.
* :func:`decrypt_config_secrets` — runs right before the API
  hands ``config`` to a driver method. Strips the ``__enc__:``
  prefix and decrypts; raises :class:`SecretFieldError` if any
  required-secret-field is unreadable (operator must re-save).
* :func:`redact_config_secrets` — runs on every API read.
  Replaces any ``secret`` field's value with the sentinel so
  operators only see ``"<set>"`` / ``""`` and never have a way
  to retrieve the cleartext through the surface.
* :func:`merge_config_for_update` — PATCH semantics. If the
  operator submits a payload that omits a secret field (or
  sends the redaction sentinel), keep the existing
  encrypted-at-rest value. Otherwise the new value flows
  through encrypt + store.
"""

from __future__ import annotations

from typing import Any

from app.core.crypto import decrypt_str, encrypt_str
from app.services.backup.targets.base import (
    BackupDestination,
    DestinationConfigError,
    config_field_specs,
)

#: Prefix on stored config strings that have been Fernet-wrapped.
#: Detection-by-prefix is enough because Fernet ciphertext is
#: itself URL-safe-base64 and never starts with ``__``.
ENC_PREFIX = "__enc__:"

#: Sentinel returned to operators in API responses to indicate
#: a secret value is set without revealing its content.
REDACTED_SENTINEL = "<set>"


class SecretFieldError(Exception):
    """Raised when a stored secret can't be decrypted or is
    missing where the driver requires one. Surfaces as 409 in
    the API layer so the operator knows to re-save the target.
    """


def secret_field_names(driver: BackupDestination) -> set[str]:
    # ``config_field_specs`` rather than ``config_fields``: a notice is
    # prose, never a value, and must not participate in secret handling
    # or the PATCH merge (#989 review).
    return {f.name for f in config_field_specs(driver) if f.secret}


def encrypt_config_secrets(driver: BackupDestination, config: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``config`` with every secret field
    Fernet-wrapped. Non-secret fields and missing keys are
    untouched. Empty/missing secret values are left as-is so an
    operator submitting "" effectively clears the secret.
    """
    secrets = secret_field_names(driver)
    out: dict[str, Any] = dict(config)
    for name in secrets:
        value = out.get(name)
        if not value or not isinstance(value, str):
            continue
        if value.startswith(ENC_PREFIX):
            # Already wrapped (e.g. PATCH carried over from
            # ``merge_config_for_update``); skip re-wrap.
            continue
        out[name] = ENC_PREFIX + encrypt_str(value).decode("utf-8")
    return out


def decrypt_config_secrets(driver: BackupDestination, config: dict[str, Any]) -> dict[str, Any]:
    """Inverse of :func:`encrypt_config_secrets`. Returns a copy
    with secret fields decrypted; raises :class:`SecretFieldError`
    if any wrapped value can't be decrypted.
    """
    secrets = secret_field_names(driver)
    out: dict[str, Any] = dict(config)
    for name in secrets:
        value = out.get(name)
        if not value or not isinstance(value, str):
            continue
        if not value.startswith(ENC_PREFIX):
            # Stored cleartext (legacy or test fixture). Pass
            # through — the driver call will succeed if the
            # value is valid plaintext.
            continue
        try:
            out[name] = decrypt_str(value[len(ENC_PREFIX) :].encode("utf-8"))
        except ValueError as exc:
            raise SecretFieldError(
                f"could not decrypt secret field {name!r} — "
                f"re-save the target with a fresh value"
            ) from exc
    return out


def redact_config_secrets(driver: BackupDestination, config: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``config`` with secret fields replaced
    by :data:`REDACTED_SENTINEL` if they're set, or empty string
    otherwise. Use on every list / get response.
    """
    secrets = secret_field_names(driver)
    out: dict[str, Any] = dict(config)
    for name in secrets:
        value = out.get(name)
        out[name] = REDACTED_SENTINEL if value else ""
    return out


def merge_config_for_update(
    driver: BackupDestination,
    *,
    incoming: dict[str, Any],
    existing: dict[str, Any],
) -> dict[str, Any]:
    """PATCH-flavoured merge. Non-secret fields take the incoming
    value when present. Secret fields take the incoming value
    only when it's a non-empty plaintext string that *isn't* the
    redaction sentinel — anything else means "keep the existing
    encrypted value". Operators editing a target's name without
    re-typing the access key are the canonical case.

    An empty string keeps the secret, because it is what the console's
    Edit sends for a secret field left blank. A stored secret is taken
    away (#3289) by an explicit ``null`` for that field, or by moving the
    destination to another auth mode: a new value for one of the
    driver's ``secret_alternatives`` drops the secrets of the others, and
    a new value for two is refused.
    """
    secrets = secret_field_names(driver)
    merged: dict[str, Any] = dict(existing)
    for key, value in incoming.items():
        if key in secrets:
            if value is None:
                merged.pop(key, None)
            elif _is_new_secret_value(value):
                merged[key] = value
            # else: drop the field from the merge so the existing
            # encrypted value carries over from ``merged = dict(existing)``.
        else:
            merged[key] = value
    supplied = {k for k in secrets if k in incoming and _is_new_secret_value(incoming[k])}
    modes = [alt for alt in driver.secret_alternatives if supplied.intersection(alt)]
    if len(modes) > 1:
        names = " and ".join(f"'{alt[0]}'" for alt in modes)
        raise DestinationConfigError(f"set ONE of {names}, not both")
    if modes:
        for alt in driver.secret_alternatives:
            if alt is not modes[0]:
                for name in alt:
                    merged.pop(name, None)
    for name in driver.unused_secret_fields(merged):
        merged.pop(name, None)
    return merged


def _is_new_secret_value(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value != REDACTED_SENTINEL
        and not value.startswith(ENC_PREFIX)
    )
