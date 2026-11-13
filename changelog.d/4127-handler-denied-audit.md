### Fixed

- Corrected the permission-refusal documentation and the `ensure_superadmin` docstring to say that a 403 raised inside a handler is recorded as a `denied` audit row, and added test coverage for the domains route.
