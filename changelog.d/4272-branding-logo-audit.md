### Fixed

- The Branding logo's audit rows now follow the Branding row's rule: an upload records the replaced logo's sha256 and size as the old value, uploading the logo already stored is a no-op that writes no row, and a delete records the removed logo's sha256 and size (#4272).
