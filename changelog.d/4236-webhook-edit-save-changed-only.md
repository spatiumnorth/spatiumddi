### Fixed

- **Edit webhook subscription, backup destination, AI provider and
  authentication provider no longer put back another client's changes
  (#4236).** Each dialog filled the form from the list's copy and saved
  every field, so a field changed elsewhere since the list loaded (a URL,
  description, enabled flag, schedule, priority, ...) was silently reverted
  by an unrelated edit. Each now reads the object when it opens and sends
  only the fields you changed; a Save with nothing changed sends nothing and
  writes no audit row. `PUT /webhooks/{id}` applies only the fields it is
  sent. Secrets, passwords, API keys and custom headers stay write-only
  (blank keeps them), and moving a destination while a credential is stored
  still needs it re-entered. An auth provider's config is still replaced
  whole, and is sent only when you edited it.
