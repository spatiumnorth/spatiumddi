"""Move stored credentials onto the dedicated CREDENTIAL_ENCRYPTION_KEY (#1358).

    python -m app.core.rotate_credential_key

Until an install sets ``CREDENTIAL_ENCRYPTION_KEY``, every stored credential
(LDAP binds, integration tokens, AI provider keys, TSIG secrets, backup-target
passwords, ...) is encrypted under a key derived from ``SECRET_KEY``, so
anything that can recover ``SECRET_KEY`` (it also signs every session token)
can open all of them.

Setting ``CREDENTIAL_ENCRYPTION_KEY`` is safe on a running install: new writes
use it, and the SECRET_KEY-derived key stays a read fallback, so nothing
already stored stops working. This command then re-encrypts the existing
values under the dedicated key, using the same column walk a cross-install
restore uses (:func:`app.services.backup.rewrap.rewrap_secrets`). It is
idempotent and resumable: a value already under the dedicated key is counted
and left alone, so a re-run after an interruption (or after a new credential
was written under the legacy key by an older pod) is safe, and it can be run
while the stack is up: each value is swapped only if it is still the one
read, so a credential the app changes meanwhile is never put back. The
fallback stays in place afterwards.

During the rollout that ADDED the key to a running install (the chart or the
appliance stamps ``CREDENTIAL_KEY_SINCE`` with that release) this refuses,
because a pod that has not restarted since could not read what it moves.

To replace a dedicated key that is already in use, set the new one as
CREDENTIAL_ENCRYPTION_KEY and pass the old one as
``OLD_CREDENTIAL_ENCRYPTION_KEY`` (environment only, never argv). Do that
with the stack stopped: values written under the old key while it runs would
be orphaned.

Keys are read from the environment, never from argv, so they do not land in
shell history or the process list, and are never printed or audited.
"""

from __future__ import annotations

import asyncio
import os
import sys

from app.config import credential_key_problem, credential_key_writes_deferred, settings
from app.core.rotate_secret_key import record_rotation_audit
from app.services.backup.rewrap import RewrapOutcome, rewrap_secrets


async def _audit(outcome: RewrapOutcome) -> None:
    await record_rotation_audit(
        outcome,
        user_display_name="<cli: rotate_credential_key>",
        action="rotate_credential_key",
        resource_id="credential_encryption_key",
        display="CREDENTIAL_ENCRYPTION_KEY",
    )


async def rotate(old_credential_key: str = "") -> int:
    """Re-encrypt stored credentials under the current dedicated key.
    Returns an exit code."""
    new_key = settings.credential_encryption_key.strip()
    if not new_key or credential_key_problem(new_key) is not None:
        print(
            "CREDENTIAL_ENCRYPTION_KEY is not set to a valid Fernet key. Generate one "
            'with `python3 -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"`, set it, and run this again.',
            file=sys.stderr,
        )
        return 2
    if credential_key_writes_deferred(settings.credential_key_since, settings.version):
        # The rollout that added the key may still have pods that cannot read
        # it; moving values onto it now would make them unreadable there.
        print(
            f"CREDENTIAL_KEY_SINCE is {settings.credential_key_since!r}, the version this "
            "process runs: the key was added during this release's rollout, so values stay "
            "under the SECRET_KEY-derived key until the next upgrade. Once every api, worker "
            "and beat pod has restarted since the key was added, you may run this with "
            "CREDENTIAL_KEY_SINCE= (empty) in this command's environment.",
            file=sys.stderr,
        )
        return 2
    if old_credential_key.strip() == new_key:
        print(
            "OLD_CREDENTIAL_ENCRYPTION_KEY is the key already in use; leave it unset to "
            "move values off the SECRET_KEY-derived key.",
            file=sys.stderr,
        )
        return 2

    # Source: the old dedicated key (if any) with SECRET_KEY-derived as its
    # fallback. Dest: the current dedicated key. Values already under it fail
    # the source and are counted as already moved.
    outcome = await rewrap_secrets(
        db_url=settings.database_url,
        source_secret_key=settings.secret_key,
        source_credential_key=old_credential_key,
        dest_secret_key=settings.secret_key,
        dest_credential_key=new_key,
    )

    audited = True
    try:
        await _audit(outcome)
    except Exception as exc:  # noqa: BLE001 — report, never mask the outcome below
        audited = False
        print(f"Could not record the audit row: {exc!r}", file=sys.stderr)
    print(
        f"Re-encrypted {outcome.rewrapped_rows} stored values and "
        f"{outcome.rewrapped_jsonb_fields} embedded ones; "
        f"{outcome.skipped_idempotent_rows} were already under the dedicated key."
    )
    if outcome.aborted or outcome.failed_rows:
        print(
            f"NOT COMPLETE: {outcome.failed_rows} values could be decrypted with neither "
            f"key{' and the walk stopped early' if outcome.aborted else ''}. If the install "
            "used a different dedicated key before, pass it as "
            "OLD_CREDENTIAL_ENCRYPTION_KEY. Values already moved are skipped on a re-run.",
            file=sys.stderr,
        )
        for failure in outcome.failures[:20]:
            print(f"  {failure}", file=sys.stderr)
        return 1
    if not audited:
        print(
            "Credentials were re-encrypted, but the audit row was not written. "
            "Run this again once the database is reachable; it moves nothing twice.",
            file=sys.stderr,
        )
        return 1
    print("Done.")
    return 0


def main() -> int:
    return asyncio.run(rotate(os.environ.get("OLD_CREDENTIAL_ENCRYPTION_KEY", "")))


if __name__ == "__main__":
    raise SystemExit(main())
