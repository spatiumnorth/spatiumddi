### Fixed

- An appliance supervisor joined to a control plane published behind an OpenShift Route, Kubernetes Ingress or reverse proxy no longer logs `supervisor.tls.pin_not_vouched` at error level for the router's certificate, which the appliance CA cannot vouch for. It is now a warning that names both that topology and an interception at pairing, and the refusal to adopt a rotated router certificate now spells out the manual re-pin. Behaviour is unchanged: verification is not weakened.
