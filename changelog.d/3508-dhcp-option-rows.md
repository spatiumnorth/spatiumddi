### Fixed

- **A pick or an edit in a DHCP custom option row changes that row
  only (#3508).** In New Client Class, New DHCP Scope and the option
  templates, with two blank custom option rows, a pick in the second
  row's option search was written into the first row, and so was a
  code or a value typed into the second row. Each row is now found by
  its place in the list.
