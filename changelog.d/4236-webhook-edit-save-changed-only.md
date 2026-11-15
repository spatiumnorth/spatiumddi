### Fixed

- **Edit webhook subscription no longer puts back another client's changes
  (#4236).** The dialog filled the form from the list's copy and saved every
  field, so a URL, description, enabled flag, event filter, timeout or retry
  limit changed elsewhere since the list loaded was silently reverted by an
  unrelated edit. It now reads the subscription when it opens and sends only
  the fields you changed; `PUT /webhooks/{id}` applies only the fields it is
  sent. A Save with nothing changed sends nothing and writes no audit row.
  The secret and custom headers stay write-only (blank keeps them), and
  moving the URL while headers are stored still needs them re-entered.
