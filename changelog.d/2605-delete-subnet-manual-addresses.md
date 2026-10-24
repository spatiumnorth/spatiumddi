### Fixed

- **Delete Subnet no longer calls manual addresses "unaffected"
  (#2605).** The first step said they were untouched, while the delete
  moves them to Trash with the subnet and their DNS records stop
  resolving until a restore, as the second step said. Step 1 now says
  the same.
