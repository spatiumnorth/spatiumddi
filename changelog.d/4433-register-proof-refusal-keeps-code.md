### Fixed

- A supervisor whose clock is off by more than five minutes no longer drops its pairing code when the control plane refuses its registration proof: the control plane now names the reason (`clock_skew`, `bad_signature`, `replayed`) in an `X-Register-Refusal` header and the 403 body, and the supervisor keeps its code, logs a clock hint and retries with a one-to-four-minute backoff, so a corrected clock registers without running `spatium-pair` again (#4433).
