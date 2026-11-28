### Fixed

- Resize subnet's preview now reports reverse zones from the same lookups the resize itself runs: a zone counts as existing only if the subnet's DNS group holds it (not in Trash), "create" lists only zones the resize will make, and a subnet with no DNS group or opted out of its reverse zone shows none (#4987).
