### Fixed
- A DNS record create or update that committed just before its zone was permanently deleted answered a bare 500 (`Could not refresh instance`); it now answers `404 Zone not found` (#3801).
