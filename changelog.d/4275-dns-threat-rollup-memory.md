### Fixed

- The DNS threat rollup no longer runs the worker out of memory on a busy hour: it now streams the hour's query log in small batches instead of loading every row, so memory is bounded by one client rather than the whole hour.
