### Fixed

- **The after-commit event publisher and audit forwarder no longer open an
  unbounded number of database connections (#2782).** Each commit that wrote
  an audit row built a fresh engine outside the api's pool, so under a bulk
  write load an api pod held its 30 pooled connections plus six or seven
  more, with no ceiling. Both hooks now share one pool of two connections per
  process; extra work waits for a free one (up to 60 s, then a warning is
  logged) and never blocks the request. A commit with no enabled webhook
  subscription, or no enabled forward target, opens no connection at all (the
  empty answer is remembered for 5 s, and cleared at once when a subscription,
  target or the legacy forward settings are saved on that api process), and
  the forwarder reads its targets over one connection instead of up to three.
  The pool is closed on api and Celery worker shutdown. Count two extra
  connections per api, worker and beat process when sizing Postgres.
