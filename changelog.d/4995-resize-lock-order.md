### Fixed
- A subnet resize whose new CIDR keeps one reverse zone and creates the next now locks the existing zone before it writes its audit row, so a concurrent record change on that zone can no longer deadlock with it. (#4995)
