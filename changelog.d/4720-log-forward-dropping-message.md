### Fixed

- An open `log_forward_dropping` alert now shows the target's current dropped count and latest drop time instead of a cryptic `[now: …]` suffix on its first message, without opening a new event or notifying again. The rule's description, the alert message and the docs now name both ways an entry is dropped: the target's queue is full, or its sends failed three times.
