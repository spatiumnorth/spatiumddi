### Fixed

- An integration sync no longer fails on every tick when the only subnet left under its wrapper block is in the Trash: the block is kept until the Trash entry is purged, the subnet still restores into it, and a network that returns is mirrored back into the same block. A wrapper block with an operator's block under it is no longer deleted along with it. A sync that releases rows left outside its target's IP space now writes its audit row at commit, so it cannot deadlock against a concurrent DNS record create in all seven mirrors (#3556).
