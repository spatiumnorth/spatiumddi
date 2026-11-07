### Fixed

- Creating a backup destination with a secret field that starts with the internal `__enc__:` marker is now refused with a 422. For a GCS destination it skipped the service-account key check and stored the planted text as the key (#3695).
