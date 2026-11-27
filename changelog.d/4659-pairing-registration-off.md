### Fixed

- Minting an appliance pairing code while appliance registration is off now warns, in the UI and in the API response, that appliances using it cannot register yet. A fresh Compose install (`INITIAL_SUPERVISOR_REGISTRATION=true`) or Helm install (`supervisorRegistration.initiallyEnabled: true`) can start with registration on; it stays off by default and the value never overrides a later choice.
