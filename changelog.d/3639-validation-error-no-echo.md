### Fixed

- A request the API refuses as invalid no longer repeats the submitted value back in its error body, so a mistyped or oversized secret field is not echoed; the backup page also caps its passphrase boxes at the API limit and formats list-shaped errors on download failures.
