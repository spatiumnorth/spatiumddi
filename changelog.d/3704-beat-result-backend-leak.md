### Fixed

- Celery beat no longer grows by ~40 MiB a day until its container is OOM-killed, and the api no longer grows the same way as it queues tasks. Sending a task subscribed to its result on a Redis pub/sub connection that only a caller waiting on the result ever reads, and nothing here waits, so every send left an entry behind for the life of the process. Tasks are now sent without that subscription; workers still store results, and the api still reads a task's state, as before. ([#3704](https://github.com/spatiumnorth/spatiumddi/issues/3704))
