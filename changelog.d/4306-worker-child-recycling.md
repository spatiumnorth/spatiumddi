### Fixed

- The Celery worker now replaces a prefork child after 1000 tasks or once it passes 400 MiB, so a slow leak in one child can no longer grow a worker pod without bound. Tune with `worker.maxTasksPerChild` / `worker.maxMemoryPerChildKiB` in the chart, or `WORKER_MAX_TASKS_PER_CHILD` / `WORKER_MAX_MEMORY_PER_CHILD_KIB` in `.env`; `0` turns either off.
