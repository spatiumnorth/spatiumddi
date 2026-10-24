### Fixed

- **A rejected DNS bundle no longer rewrites the live TSIG key files
  (#2648).** The BIND9 agent wrote `ddns.key` and removed
  `view-transfer.key` before `named-checkconf` ran, so a refused bundle
  left record ops signing with the wrong key, or `named` missing an
  included file at its next start. The key files are now staged in
  `rendered.new` and go live (and revert) with the tree swap.
