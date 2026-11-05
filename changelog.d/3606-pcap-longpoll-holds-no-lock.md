### Fixed
- The appliance packet-capture long-poll no longer holds its database read transaction while it waits for a queued capture, so a restore or an `ALTER TABLE` on `packet_capture` no longer waits out every parked poll. The supervisor heartbeat long-poll was checked and already released its transaction before the wait; a regression test now pins both (#3606).
