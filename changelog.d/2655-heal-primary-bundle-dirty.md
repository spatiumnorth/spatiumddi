### Fixed

- **The primary self-heal now marks the healed group's bundles dirty and wakes its agents (#2655).** A catalog-zone group left without a primary kept a producer-less bundle until an unrelated change re-rendered it.
