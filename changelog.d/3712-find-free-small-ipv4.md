### Fixed

- Find Free opened from an IPv4 block longer than /24 now starts on a size the block can hold (one step below the block, held to /30) instead of /24, and an empty answer says when the block is smaller than the size searched (#3712).
