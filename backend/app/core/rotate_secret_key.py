"""Move an install onto a new SECRET_KEY without losing stored credentials (#1222).

    OLD_SECRET_KEY='<the key being replaced>' python -m app.core.rotate_secret_key

Run it with SECRET_KEY already set to the NEW key, before starting the api.
The api refuses to boot on a placeholder or weak SECRET_KEY, so an install
that has been running on one has to move to a real key, and SECRET_KEY does
two jobs:

* it signs session tokens. Those just stop verifying, so everyone signs in
  again. Nothing to do.
* unless ``CREDENTIAL_ENCRYPTION_KEY`` is set, it derives the Fernet key
  every stored credential (LDAP binds, integration tokens, AI provider keys,
  TSIG secrets, ...) is encrypted with. Those would all become unreadable.

So this re-encrypts every stored credential from the key derived from
OLD_SECRET_KEY to the key the current settings derive, using the same
column walk a cross-install restore uses
(:func:`app.services.backup.rewrap.rewrap_secrets`). It is idempotent: a
value already under the new key is counted and left alone, so a re-run
after an interruption is safe.

When ``CREDENTIAL_ENCRYPTION_KEY`` is set and unchanged, the Fernet key does
not depend on SECRET_KEY and there is nothing to re-encrypt. If it is being
changed too, pass the old one as ``OLD_CREDENTIAL_ENCRYPTION_KEY``.

Keys are read from the environment, never from argv, so they do not land in
shell history or the process list.
"""

from __future__ import annotations

import asyncio
import os
import sys

from app.config import secret_key_problem, settings
from app.services.backup.rewrap import RewrapOutcome, rewrap_secrets


async def _audit(outcome: RewrapOutcome) -> None:
    """Record the rotation (non-negotiable #4). Counts only, never keys."""
    # task_session, not the shared engine: this runs under its own
    # asyncio.run loop, exactly the case that helper exists for.
    from app.db import task_session  # noqa: PLC0415 — needs the DB, not at import
    from app.models.audit import AuditLog  # noqa: PLC0415

    async with task_session() as db:
        db.add(
            AuditLog(
                user_display_name="<cli: rotate_secret_key>",
                auth_source="system",
                action="rotate_secret_key",
                resource_type="platform",
                resource_id="secret_key",
                resource_display="SECRET_KEY",
                result="error" if outcome.aborted or outcome.failed_rows else "success",
                new_value={
                    "rewrapped_rows": outcome.rewrapped_rows,
                    "rewrapped_jsonb_fields": outcome.rewrapped_jsonb_fields,
                    "already_under_new_key": outcome.skipped_idempotent_rows,
                    "failed_rows": outcome.failed_rows,
                    "aborted": outcome.aborted,
                },
            )
        )
        await db.commit()


async def rotate(old_secret_key: str, old_credential_key: str) -> int:
    """Re-encrypt stored credentials for the new key. Returns an exit code."""
    problem = secret_key_problem(settings.secret_key)
    if problem is not None:
        print(
            f"SECRET_KEY (the NEW key) is not safe to use: {problem}. "
            "Set it to `openssl rand -hex 32` first.",
            file=sys.stderr,
        )
        return 2
    if old_secret_key == settings.secret_key and (
        old_credential_key.strip() == settings.credential_encryption_key.strip()
    ):
        print(
            "OLD_SECRET_KEY is the key already in use; set SECRET_KEY to the new key "
            "and OLD_SECRET_KEY to the one being replaced.",
            file=sys.stderr,
        )
        return 2

    outcome = await rewrap_secrets(
        db_url=settings.database_url,
        source_secret_key=old_secret_key,
        source_credential_key=old_credential_key,
        dest_secret_key=settings.secret_key,
        dest_credential_key=settings.credential_encryption_key,
    )
    if outcome.same_install:
        print(
            "Nothing to re-encrypt: CREDENTIAL_ENCRYPTION_KEY is set and unchanged, so "
            "stored credentials do not depend on SECRET_KEY. Start the stack."
        )
        return 0

    await _audit(outcome)
    print(
        f"Re-encrypted {outcome.rewrapped_rows} stored values and "
        f"{outcome.rewrapped_jsonb_fields} embedded ones; "
        f"{outcome.skipped_idempotent_rows} were already under the new key."
    )
    if outcome.aborted or outcome.failed_rows:
        print(
            f"NOT COMPLETE: {outcome.failed_rows} values could be decrypted with neither "
            f"key{' and the walk stopped early' if outcome.aborted else ''}. Check "
            "OLD_SECRET_KEY, then run this again; values already moved are skipped.",
            file=sys.stderr,
        )
        for failure in outcome.failures[:20]:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print("Done. Start the stack; everyone signs in again.")
    return 0


def main() -> int:
    old = os.environ.get("OLD_SECRET_KEY", "")
    if not old:
        print(__doc__, file=sys.stderr)
        print("OLD_SECRET_KEY is not set.", file=sys.stderr)
        return 2
    old_credential = os.environ.get(
        "OLD_CREDENTIAL_ENCRYPTION_KEY", settings.credential_encryption_key
    )
    return asyncio.run(rotate(old, old_credential))


if __name__ == "__main__":
    raise SystemExit(main())
