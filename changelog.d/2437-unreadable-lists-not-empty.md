### Fixed

- **New Group's Members list said "No users" over a refused read, and
  `/ipam` said "Select a space, block, or subnet from the tree." over an
  empty tree whose reads were all refused (#2437).** Both now say the list
  could not be read (the same sentence the Users page uses since #1343),
  and only an answered, genuinely empty list keeps its empty-state text.
