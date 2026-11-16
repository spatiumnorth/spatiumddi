### Fixed

- **`helm lint` failed on the umbrella chart once an agent server was listed (#4278).** `dns-agent.yaml` and `dhcp-agent.yaml` emitted the `---` between objects in a way that `{{-` trimming glued to the next object's `apiVersion`; `helm install` accepted it, but `helm lint` (and so Red Hat's chart-verifier) rejected it with "invalid Yaml document separator". The separators now always sit on their own line, the rendered objects are unchanged, and `make charts-lint` lints the chart with DNS and DHCP servers (also with the OpenShift platform) so it cannot come back.
