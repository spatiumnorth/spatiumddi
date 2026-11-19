### Fixed

- A fresh multi-replica appliance install no longer waits for an api restart to get its first Web UI certificate when the startup bootstrap loses the reconcile lock: the certificate loop retries the bootstrap until one exists. (#4442)
