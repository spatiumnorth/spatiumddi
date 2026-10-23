### Fixed

- **A new subnet is counted in its block's Allocated at once
  (#2532).** Creating a subnet rolled its block up before the
  subnet's own network, broadcast and gateway rows were flushed, so
  the block read short until the next address write or the hourly
  recount.
