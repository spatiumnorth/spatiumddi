### Fixed

- A worker no longer stops answering pings when a Redis Sentinel master move makes the broker connection fail while a task is running. kombu's restore of the unacknowledged message raised an `AttributeError` that Celery treated as unrecoverable; the worker now logs it and reconnects, so a running upgrade drive keeps its lease.
