# Verifying a release

From the first release cut after [#1251](https://github.com/spatiumnorth/spatiumddi/issues/1251),
every container image and the Helm chart in a SpatiumDDI release is signed
and carries attestations, all **keyless** (Sigstore, using the GitHub Actions
OIDC identity of the release workflow). There is no project signing key to
distribute or rotate: you check that the signature was made by the `release.yml`
workflow of the `spatiumnorth/spatiumddi` repository, run for a release tag.

What is attached to each artifact:

| Artifact | Signature | SBOM (SPDX, signed attestation) | Build provenance |
|---|---|---|---|
| Every image `ghcr.io/spatiumnorth/<image>:<version>` | yes | yes | yes |
| The `-ubi` variants `<image>:<version>-ubi` | yes | yes | yes |
| Helm chart `oci://ghcr.io/spatiumnorth/charts/spatiumddi` | yes | no (YAML only; each image has its own) | yes |

Signing happens after the Trivy gate and before `:latest` moves, and it signs
the image **digest**, not the tag. Releases published before this feature have
no signature. The appliance ISO and slot image are not covered yet and still
only ship a `.sha256`, which proves integrity, not authenticity.

You need [cosign](https://github.com/sigstore/cosign) 2.x or newer. The
GitHub CLI is optional, for the provenance check.

```bash
VERSION=1.1.0                       # the release tag, without a leading v
IMAGE=ghcr.io/spatiumnorth/spatiumddi-api
IDENTITY='^https://github.com/spatiumnorth/spatiumddi/\.github/workflows/release\.yml@refs/tags/.+$'
ISSUER=https://token.actions.githubusercontent.com
```

## Signature

```bash
cosign verify "$IMAGE:$VERSION" \
  --certificate-identity-regexp "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER"
```

For a UBI image use `"$IMAGE:$VERSION-ubi"`. To pin the exact release tag
instead of any release tag, use `--certificate-identity
"https://github.com/spatiumnorth/spatiumddi/.github/workflows/release.yml@refs/tags/$VERSION"`.
A tag can be moved by whoever controls the registry; to be certain what you run,
resolve it once, verify, and deploy by digest (`$IMAGE@sha256:...`).

## SBOM

```bash
cosign verify-attestation "$IMAGE:$VERSION" --type spdxjson \
  --certificate-identity-regexp "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" \
  | jq -r '.payload' | base64 -d | jq '.predicate' > sbom.spdx.json
```

## Build provenance

```bash
gh attestation verify "oci://$IMAGE:$VERSION" --owner spatiumnorth
```

## Helm chart

The chart version is the release version with CalVer zero-padding removed (see
the Version Scheme in `CLAUDE.md`); a SemVer release is unchanged.

```bash
CHART=ghcr.io/spatiumnorth/charts/spatiumddi:$VERSION
cosign verify "$CHART" \
  --certificate-identity-regexp "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER"
gh attestation verify "oci://$CHART" --owner spatiumnorth
```

## Notes

- Verification contacts Sigstore's public transparency log and trust root
  (`rekor.sigstore.dev`, `tuf-repo-cdn.sigstore.dev`) **from the machine you
  run it on**. SpatiumDDI itself makes no new outbound connection; signing runs
  only in the release pipeline. See [PRIVACY](../PRIVACY.md).
- Air-gapped clusters: `cosign verify` supports an offline bundle and a
  private trust root; see the cosign documentation.
