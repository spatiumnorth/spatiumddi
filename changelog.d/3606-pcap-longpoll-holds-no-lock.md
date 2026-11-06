### Fixed
- The appliance packet-capture, kubeapi-proxy, network-tool and storage long-polls no longer hold a database read transaction while they wait for work, so a restore or an `ALTER TABLE` no longer waits out every parked poll. The supervisor heartbeat long-poll was checked and already released its transaction before the wait; a regression test now pins it too (#3606).
