### Fixed

- **Subnet split and merge no longer reset PCI / HIPAA scope,
  internet-facing, role and do-not-probe (#2414).** Split children
  inherit the parent's compliance, discovery, kind, customer and site
  settings. A merge keeps PCI / HIPAA scope, internet-facing and
  do-not-probe when any source has them, refuses sources that disagree
  on kind, customer or site, and the preview lists every other
  disagreement.
