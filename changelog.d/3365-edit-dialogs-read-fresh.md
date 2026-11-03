### Fixed

- Edit Server Group (DNS), Edit Blocking List, Edit MAC Block, Edit PXE profile and Edit address set no longer undo a change made elsewhere since their list loaded: each reads the object when it opens and its Save sends only the fields you changed (Edit DNSSEC policy and Edit NAT mapping got the same fix) (#3365)
