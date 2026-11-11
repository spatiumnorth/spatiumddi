### Fixed

- Adding a backup destination with the `<set>` placeholder as a secret now answers 422 instead of saving the placeholder as the secret. Edit still reads it as "keep the stored secret".
