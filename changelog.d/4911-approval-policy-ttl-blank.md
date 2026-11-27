### Fixed

- A TTL of 0, or a blank TTL, in the approval policy dialog was silently saved as 168 hours. The dialog now refuses it with a message and says the TTL runs from 1 to 8760 hours (#4911).
