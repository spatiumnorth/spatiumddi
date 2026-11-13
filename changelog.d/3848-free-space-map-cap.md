### Fixed

- A block's Allocation map no longer leaves the end of the block blank when its free space splits into more than 200 ranges (an IPv6 /48 with a /64 in each of 25 /56s). `GET /ipam/blocks/{id}/free-space` takes a `limit` and marks a capped answer with `more_after` on its last range; the Band and Treemap ask for up to 2,000 ranges, draw anything still left as one free span and say "Showing N of M free ranges" (#3848).
