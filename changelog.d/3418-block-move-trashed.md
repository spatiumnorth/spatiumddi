### Fixed

- **A block move no longer counts blocks in the Trash at the
  destination (#3418).** The move's overlap check read the target
  level's blocks without leaving out the trashed ones. A trashed block
  refused a move of its own CIDR, or of a block inside it, with a 409,
  though creating the same block there was allowed (#490). A trashed
  block inside the moved block's range was re-parented under it: the
  Trash row changed, its restore was then refused while the moved
  block sat in the Trash, and purging the moved block deleted it for
  good. A move now counts live blocks only and leaves rows in the
  Trash as they were. A live block in the way still refuses the move,
  or is re-parented under the moved block, as before.
