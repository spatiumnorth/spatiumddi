### Fixed

- **Migration safety (#1253).** `alembic upgrade` honours an opt-in `MIGRATION_STATEMENT_TIMEOUT_SECONDS` (off by default, since data migrations can legitimately run for minutes) alongside the existing lock timeout; the migration linter now flags a blocking `CREATE INDEX` or a validating `ADD CONSTRAINT` on large tables; and `audit_log.seq` declares its unique index on the model, so a database built without migrations has the constraint that guards the audit hash chain. See `docs/DEVELOPMENT.md` §8.
