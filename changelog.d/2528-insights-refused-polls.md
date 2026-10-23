### Fixed

- **Platform Insights stops re-asking reads the server refused, and says why (#2528).** The Postgres, Redis and Services tabs stop polling after a 403 (each poll was a denied audit row) and the Postgres and Redis tabs say the reader may not see the statistics.
