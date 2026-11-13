### Fixed

- Moving an IPAM block into a space whose block it contains no longer leaves two overlapping live subnets there: the move and its preview now refuse (409) naming the overlapping subnets, as the subnet create does, and refuse a moved child block that overlaps a block being re-parented under it (#3923).
