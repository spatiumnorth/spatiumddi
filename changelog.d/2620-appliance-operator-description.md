### Fixed

- **Roles: the built-in "Appliance Operator" no longer promises "Full control" of the appliance** — its holder is refused the upgrade-image store, every Fleet member action, MetalLB, the kube-api CIDRs and pairing (superadmin only). The description and `docs/PERMISSIONS.md` now say what the role reaches and what still needs a superadmin. The role's grant is unchanged. (#2620)
