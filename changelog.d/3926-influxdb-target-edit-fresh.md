### Fixed

- **Edit InfluxDB target no longer puts back another client's changes
  (#3926).** The dialog filled the form from the list's copy and saved
  every field, so a URL, bucket, measurement prefix or push switch changed
  elsewhere since the list loaded was silently reverted by an unrelated
  edit. It now reads the target when it opens and sends only the fields
  you changed; the update endpoint applies only the fields it is sent. A
  Save with nothing changed sends nothing. Stored tokens and passwords
  stay write-only.
