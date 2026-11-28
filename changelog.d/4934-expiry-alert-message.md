### Fixed

- An open expiry alert (decommission date, domain, TLS certificate, circuit or service term, k3s API certificate, secret, RPKI ROA) now rewrites its whole message as the date nears, so the current day count and date read clearly instead of a trailing "[now: 3 / 11 / 29]" (#4934).
