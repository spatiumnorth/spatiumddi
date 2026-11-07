### Fixed

- Celery beat no longer grows by ~40 MiB a day until the container is OOM-killed: beat now runs with its result backend switched off, so each scheduled send stops queueing an `UNSUBSCRIBE` bookkeeping entry on a Redis pub/sub connection nothing in beat ever reads. Workers still store task results as before. ([#3704](https://github.com/spatiumnorth/spatiumddi/issues/3704))
