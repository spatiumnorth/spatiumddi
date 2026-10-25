### Removed

- **The plaintext webhook forward-target columns are dropped
  (#1502).** `audit_forward_target.url` / `auth_header` and the legacy
  `platform_settings.audit_forward_webhook_url` /
  `audit_forward_webhook_auth_header` were moved to Fernet-encrypted
  columns one release ago and kept, unread, so a rolling upgrade's old
  pods kept working. The migration encrypts any value still left in one
  into its encrypted column when that column is empty, then drops it.
  An encrypted value already present is left as it is. A target the
  migration writes a value into is left disabled (the Settings webhook
  likewise), since that value may be one an admin cleared, and an
  audit-log row per target says so, so the reason outlives the migrate
  Job's log; re-enable it once the endpoint is confirmed. Archives taken
  before the drop still restore: a full restore migrates them, and a
  selective restore loads the old columns, encrypts what they hold, and
  drops them again. Either way a restore leaves a target filled from an
  old column disabled with the same audit-log row, and its warnings name
  each one. The code that blanked the plaintext copy on every write is gone with them.

### Migrations

- `c2b203844c95` — #1502, encrypt any value left in the plaintext
  webhook forward-target columns, then drop them. The downgrade
  re-adds them empty.
