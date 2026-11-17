### Fixed
- IPAM Templates "Reapply to all" now lists each instance it skipped and why, says when the 200-instance cap was reached, and shows a refused reapply's reason. A block skipped because a child subnet overlaps is left exactly as it was instead of keeping the template's stamped fields ([#3895](https://github.com/spatiumnorth/spatiumddi/issues/3895)).
