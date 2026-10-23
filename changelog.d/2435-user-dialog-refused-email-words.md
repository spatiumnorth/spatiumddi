### Fixed

- **New User, Edit User and Reset password showed a refused email as raw
  validation JSON (#2435).** The three dialogs printed a non-string error
  detail with `JSON.stringify`; they now say it in words ("email: Invalid
  email address"), the way the other dialogs do through `formatApiError`.
