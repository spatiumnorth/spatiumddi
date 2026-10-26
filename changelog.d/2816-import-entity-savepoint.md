### Fixed

- **Importers: one failed entity no longer 500s the whole commit** (#2816). The NetBox and DHCP importers answered a failed entity with `db.rollback()`, which expires every loaded object including the signed-in user; the next entity's audit row then failed too, and the route's closing log line raised `MissingGreenlet`, a 500 after earlier entities had committed. Each entity is now written in a real SAVEPOINT (`services/import_savepoint.py`), the actor is snapshotted as plain values, and a failure rolls back only that entity.
