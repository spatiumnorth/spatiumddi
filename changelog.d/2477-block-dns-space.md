### Fixed

- **A top-level block's Edit IP Block DNS tab shows its space's DNS (#2477).** With "Inherit from parent" ticked it read "No DNS settings configured in parent chain." and DNS Server Group "None" while the space gave the block a group, because the tab was never told the space. It now names the space's group, as New IP Block and the Edit dialog's DHCP tab already did. Display only; the Save was unaffected.
