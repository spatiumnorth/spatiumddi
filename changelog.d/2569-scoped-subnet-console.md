### Fixed

- **The console now reaches a subnet a grant is scoped to (#2569).**
  The console half of #2438: `/ipam?subnet=X` opens X when the
  spaces and blocks lists are refused, the global search returns the
  subnets a grant on one subnet admits (and no others), and the
  subnet header's Edit asks for write on that subnet instead of on
  all subnets. Resize, Split, Merge and the other reshaping tools stay
  disabled for such a holder, as their routes still refuse it.
