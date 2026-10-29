### Fixed

- **New User, Reset password, New Role and Clone say a refusal in words
  instead of raw JSON (#3040, #3041).** A password that breaks the
  password policy showed `{"reason":"password_policy","errors":[...]}` in
  the New User and Reset password dialogs, and a blank role name showed
  the raw validation array in New Role and Clone. They now list the
  policy's errors, or say "Role name cannot be empty", as the user
  dialogs already do for a refused email. The Group and API token create
  dialogs read errors the same way.
