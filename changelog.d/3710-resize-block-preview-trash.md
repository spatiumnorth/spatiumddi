### Fixed

- **Resize block's preview leaves the Trash out (#3710).** The preview
  counted, listed and summed child blocks and subnets that had been sent to
  the Trash, and added their address rows to "IP addresses in descendant
  subnets", so it overstated what a resize touches and named objects the
  operator had deleted. The preview, and the commit's own fit checks, now
  read live blocks and subnets only.
