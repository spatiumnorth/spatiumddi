### Fixed

- A backup destination's Add now holds the auth-mode rules its Edit holds: an Azure Blob destination with both an account key and a connection string, or an SCP destination with both a password and a private key, is refused (422) instead of stored, and an HTTPS PUT destination with auth `none` no longer stores a credential. Destinations saved earlier with two modes stay editable.
