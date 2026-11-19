### Fixed

- Celery worker children now keep one event loop and one database engine for all their tasks, instead of building and disposing both on every run, which leaked a little native memory per task and paid a fresh connection each time; code outside a worker child behaves as before ([#4515](https://github.com/spatiumnorth/spatiumddi/issues/4515)).
