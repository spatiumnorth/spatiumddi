### Fixed

- **A block move takes the subnets in the Trash with it (#3436).** A
  subnet in the Trash under the moved block, or under a block in the
  Trash inside it, kept the old space while its block moved to the new
  one. Restored, it came back live in the old space under a block in
  the new space, and the restore checked it against the old space's
  subnets only, so it could come back beside a live subnet of the same
  CIDR under the same block. A move now takes every subnet under the
  block to the new space, the Trash included: a restore brings it back
  beside its block, and is refused if a live subnet there already holds
  its CIDR. The move's counts and its integration check still cover the
  live subnets only, as before.
