### Changed

- **An open alert now shows its peak and its current reading
  (#2839).** The message of an open alert was rewritten only when its
  severity rose, so when a value improved without resolving (/var
  falling from 88% to 77%) it kept describing the worst reading and
  disagreed with the live panel. The peak is the message at the
  highest severity the alert reached; when the current reading
  differs it is shown beside it, for example `... 88% full ... [now:
  77%]`. Nothing is inferred from the numbers, so this holds for
  rules where lower is worse too. Severity and fired time are
  unchanged, the text is written only when it changes, and a text
  change never re-sends a notification.
