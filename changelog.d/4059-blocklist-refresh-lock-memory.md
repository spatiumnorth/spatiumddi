### Fixed

- Refreshing a large blocklist feed no longer risks killing the worker: only one refresh runs per list at a time (a second request while one is running is skipped), the feed is compared against the stored entries inside the database instead of in worker memory (peak down from 141 to 84 MiB on a 500k-line test feed), and a refresh that fails part-way rolls back to the previous entries and shows an error on the list instead of leaving it empty.
