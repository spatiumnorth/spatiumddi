### Fixed

- **New User answered 500 when the username belonged to one account and the
  email to another (#2434).** The uniqueness lookup matched either column
  and required a single row, so two matches raised and only the catch-all
  answered. It now refuses the crossed pair with the same 409 as either
  clash alone.
