### Fixed

- **An empty schema ahead of the tables on the `search_path` no longer
  makes every table read as missing (#2825).** The check behind
  readiness's newer-schema guard (#2813) and the restore's drift
  recovery listed tables from `current_schema()` alone. When a schema
  with no tables in it, such as one named after the database user, came
  first on the `search_path`, every table and column read as missing: a
  pod that had been Ready answered 503 while a newer release migrated
  the database, and the restore refused to stamp. With no schema given
  it now reads the tables visible on the `search_path`, as the
  inspector it replaced did. A schema named explicitly is read as
  before.
