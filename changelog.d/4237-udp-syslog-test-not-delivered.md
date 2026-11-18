### Fixed

- Settings → Audit Event Forwarding: the Test of a syslog target over UDP no longer says "delivered" with a green check. UDP only hands a datagram to the network, so the Test now answers "sent to NAME over UDP — delivery cannot be confirmed" with a neutral icon; TCP, TLS, webhook and email targets still report a confirmed delivery or the failure. (#4237)
