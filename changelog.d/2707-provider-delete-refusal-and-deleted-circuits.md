### Fixed

- **Providers:** a refused provider delete now shows the server's reason on the page instead of closing the dialog with nothing. And a provider whose circuits were all deleted can now be deleted: deleted circuits (soft-deleted, unreachable by any route) kept it blocked for good through `ON DELETE RESTRICT`; the provider delete, single and bulk, now removes them with it, while a live circuit still refuses with a 409. (#2707)
