### Fixed

- **A block inside another block can be grown with Resize (#3382).**
  The resize overlap check counted the block's own parent, and every
  block above it, as blocks in the way, so a nested block could never
  grow: the API answered 409 naming the parent, and the Resize dialog's
  preview listed the parent as a conflict and kept its button disabled.
  A block's ancestors are no longer counted. Growth past the parent's
  edge is still refused, now with "does not fit inside the parent
  block", and siblings, cousins and the subnets of the parent still
  block a growth that would overlap them.
