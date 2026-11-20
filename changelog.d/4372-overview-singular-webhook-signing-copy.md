### Fixed

- The Overview inventory strip now says "1 space" (and "1 subnet", "1 DNS zone", "1 server") for a count of one, and the Webhooks page no longer promises every enabled subscription an HMAC-signed POST: deliveries are signed when the subscription has a secret and unsigned when it has none (#4372, #4373).
