### Fixed

- **A log that ends inside a private key no longer shows the key's short
  last line.** When a log stops after a key's BEGIN line with no END, the
  body lines after the marker are replaced by `[REDACTED]:pem`, but a last
  body line shorter than 16 characters ended that run and was shown right
  after the marker. The host log viewer, a pod's one-shot log and the
  diagnostic bundle now remove it too: a base64 token shorter than the
  key's full-width lines, with the same log prefix in front of it. An
  ordinary log line after the key says more than one such word and is kept.
