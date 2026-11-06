### Fixed

- A DNSSEC key-lifetime render test no longer fails now and then because a random identifier or the timestamp in the rendered config happened to contain `-1d`. It now checks only the `lifetime` clauses. (#3629)
