### Fixed

- Platform Insights › Containers is no longer Docker-only: it reports which of Docker, Kubernetes and the appliance it can see (naming `api.serviceAccount.enabled` when Kubernetes is off), and on a Helm install lists the release's pods and tails their logs, redacted, from the browser (#3761).
