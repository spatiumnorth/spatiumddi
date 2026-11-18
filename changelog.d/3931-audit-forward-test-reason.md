### Fixed
- Audit Event Forwarding: a target's Test now says why delivery failed (timeout, refused connection, HTTP status with the receiver's answer, a missing SMTP setting) instead of `delivery failed: failed`; secrets stay redacted ([#3931](https://github.com/spatiumnorth/spatiumddi/issues/3931)).
