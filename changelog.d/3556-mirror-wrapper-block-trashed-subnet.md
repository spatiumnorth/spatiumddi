### Fixed

- An integration sync no longer fails on every tick when the only subnet left under its wrapper block is in the Trash: the block is released to the operator (kept, with an audit row) instead of being deleted into a foreign-key error, in all seven mirrors. A sync that releases rows left outside its target's IP space now also writes that audit row at commit, so it cannot deadlock against a concurrent DNS record create (#3556).
