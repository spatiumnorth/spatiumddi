### Fixed

- Bulk allocate: the default Range start / Range end are now clamped to the subnet's usable addresses, so Preview with the untouched dialog on a subnet smaller than /27 (a /29 ends at .7) is no longer refused with "Range must be inside subnet" (#2422).
