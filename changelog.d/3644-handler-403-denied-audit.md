### Fixed

- A 403 decided inside a handler (a hand-written `user_has_permission` check) now writes a `denied` audit row like a router-level gate does; one 403 exception handler writes it centrally, and skips it when a gate already wrote one (#3644).
